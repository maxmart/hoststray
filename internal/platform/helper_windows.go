package platform

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// The helper is a small Windows service, running as SYSTEM, that writes the
// hosts file for the user who installed it and closes connections to the
// addresses a hostname moved away from. It is what "Change hosts without
// password" turns on. Its exe is a copy of hoststray.exe in Program Files: a
// SYSTEM service must not run an exe the user could replace, and the app's
// own folder is the user's.
//
// The app talks to it over a named pipe only that user can open, one JSON
// request and one response per connection.

const (
	helperService = "HostsTrayHelper"
	helperPipe    = `\\.\pipe\HostsTrayHelper`
	helperProto   = 1 // bump when requests change; the helper only updates on reinstall
)

var errNoHelper = errors.New("hosts helper not running")

type helperRequest struct {
	Op    string   `json:"op"` // "version" or "write"
	Hosts string   `json:"hosts,omitempty"`
	Drop  []string `json:"drop,omitempty"`
}

type helperResponse struct {
	Proto  int    `json:"proto,omitempty"`
	Closed int    `json:"closed,omitempty"`
	Error  string `json:"error,omitempty"`
}

func helperDir() string {
	pf := os.Getenv("ProgramFiles")
	if pf == "" {
		pf = `C:\Program Files`
	}
	return filepath.Join(pf, "Hosts Tray Helper")
}

func helperExe() string { return filepath.Join(helperDir(), "hoststray-helper.exe") }

// --- app side -----------------------------------------------------------------

// helperPID returns the process ID of the running helper service.
func helperPID() (uint32, error) {
	m, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return 0, errNoHelper
	}
	defer windows.CloseServiceHandle(m)
	name, _ := windows.UTF16PtrFromString(helperService)
	s, err := windows.OpenService(m, name, windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return 0, errNoHelper
	}
	defer windows.CloseServiceHandle(s)
	var st windows.SERVICE_STATUS_PROCESS
	var n uint32
	if err := windows.QueryServiceStatusEx(s, windows.SC_STATUS_PROCESS_INFO, (*byte)(unsafe.Pointer(&st)), uint32(unsafe.Sizeof(st)), &n); err != nil {
		return 0, errNoHelper
	}
	if st.CurrentState != windows.SERVICE_RUNNING {
		return 0, errNoHelper
	}
	return st.ProcessId, nil
}

func helperReady(path string) bool {
	if !IsSystemHosts(path) {
		return false
	}
	_, err := helperPID()
	return err == nil
}

// pipeAccess is read/write without FILE_CREATE_PIPE_INSTANCE, so clients
// can't serve the pipe themselves.
const pipeAccess = windows.FILE_GENERIC_READ | windows.FILE_WRITE_DATA

func helperCall(req helperRequest) (helperResponse, error) {
	var resp helperResponse
	pid, err := helperPID()
	if err != nil {
		return resp, err
	}
	name, _ := windows.UTF16PtrFromString(helperPipe)
	var h windows.Handle
	for i := 0; ; i++ {
		h, err = windows.CreateFile(name, pipeAccess, 0, nil, windows.OPEN_EXISTING, 0, 0)
		if (err == windows.ERROR_PIPE_BUSY || err == windows.ERROR_FILE_NOT_FOUND) && i < 40 {
			time.Sleep(50 * time.Millisecond)
			continue
		}
		break
	}
	if err != nil {
		return resp, fmt.Errorf("hosts helper: %w", err)
	}
	f := os.NewFile(uintptr(h), helperPipe)
	defer f.Close()
	// Only trust the service itself: anyone could have created a pipe by this
	// name while it wasn't running.
	var server uint32
	if err := windows.GetNamedPipeServerProcessId(h, &server); err != nil || server != pid {
		return resp, errors.New("hosts helper: the pipe isn't served by the helper service")
	}
	if err := json.NewEncoder(f).Encode(req); err != nil {
		return resp, fmt.Errorf("hosts helper: %w", err)
	}
	if err := json.NewDecoder(f).Decode(&resp); err != nil {
		return resp, fmt.Errorf("hosts helper: %w", err)
	}
	if resp.Error != "" {
		return resp, errors.New(resp.Error)
	}
	return resp, nil
}

func helperWrite(path string, content []byte, drop []netip.Addr) error {
	if !IsSystemHosts(path) {
		return errNoHelper
	}
	req := helperRequest{Op: "write", Hosts: string(content)}
	for _, a := range drop {
		req.Drop = append(req.Drop, a.String())
	}
	_, err := helperCall(req)
	return err
}

// helperSetGroup: the Windows helper takes whole-file writes (helperWrite)
// for now.
func helperSetGroup(path, name string, enable bool) (bool, error) { return false, nil }

func helperOutdated() bool { return false }

func currentSID() (string, error) {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return "", err
	}
	return u.User.Sid.String(), nil
}

// setHelper installs or removes the helper through a UAC prompt.
func setHelper(enable bool) error {
	sid, err := currentSID()
	if err != nil {
		return err
	}
	op := "--uninstall-helper"
	if enable {
		op = "--install-helper"
	}
	return runElevatedExe(executable(), op+" "+sid)
}

func helperInstalled() bool {
	m, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return false
	}
	defer windows.CloseServiceHandle(m)
	name, _ := windows.UTF16PtrFromString(helperService)
	s, err := windows.OpenService(m, name, windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return false
	}
	windows.CloseServiceHandle(s)
	return true
}

// --- elevated commands ----------------------------------------------------------

// sidPattern matches local, domain and Microsoft Entra user accounts.
var sidPattern = regexp.MustCompile(`^S-1-(5-21|12-1)(-\d+){4}$`)

// helperCommand runs the helper-related command line modes; ok is false for
// any other command line.
func helperCommand(args []string) (code int, ok bool) {
	if len(args) == 0 {
		return 0, false
	}
	arg := func() string {
		if len(args) < 2 {
			return ""
		}
		return args[1]
	}
	var err error
	switch args[0] {
	case "--helper-service":
		err = svc.Run(helperService, &helperSvc{sid: arg()})
	case "--install-helper":
		err = installHelper(arg())
	case "--uninstall-helper":
		err = uninstallHelper(arg())
	case "--remove-helper": // the uninstaller: prompts only if there is one
		if helperInstalled() {
			err = setHelper(false)
		}
	case "--close-connections":
		var addrs []netip.Addr
		for _, s := range strings.Split(arg(), ",") {
			if a, err := netip.ParseAddr(s); err == nil {
				addrs = append(addrs, a)
			}
		}
		_, err = closeConnections(addrs)
	default:
		return 0, false
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1, true
	}
	return 0, true
}

func installHelper(sid string) error {
	if !sidPattern.MatchString(sid) {
		return fmt.Errorf("bad user SID %q", sid)
	}
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(helperService)
	if err == nil {
		stopService(s) // so its exe can be replaced
	}
	if err := os.MkdirAll(helperDir(), 0o755); err != nil {
		return err
	}
	if err := copyFile(executable(), helperExe()); err != nil {
		return err
	}
	if s == nil {
		s, err = m.CreateService(helperService, helperExe(), mgr.Config{
			DisplayName: "Hosts Tray Helper",
			Description: "Lets Hosts Tray change the hosts file and reset browser connections without a UAC prompt.",
			StartType:   mgr.StartAutomatic,
		}, "--helper-service", sid)
		if err != nil {
			return err
		}
	} else {
		cfg, err := s.Config()
		if err != nil {
			return err
		}
		cfg.BinaryPathName = `"` + helperExe() + `" --helper-service ` + sid
		cfg.StartType = mgr.StartAutomatic
		if err := s.UpdateConfig(cfg); err != nil {
			return err
		}
	}
	defer s.Close()
	if err := s.Start(); err != nil {
		return err
	}
	for i := 0; i < 50; i++ {
		if st, err := s.Query(); err == nil && st.State == svc.Running {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	// The helper replaces the old way of skipping the prompt.
	return removeGrant(sid)
}

func uninstallHelper(sid string) error {
	if !sidPattern.MatchString(sid) {
		return fmt.Errorf("bad user SID %q", sid)
	}
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	if s, err := m.OpenService(helperService); err == nil {
		stopService(s)
		err = s.Delete()
		s.Close()
		if err != nil {
			return err
		}
	}
	for i := 0; i < 20; i++ { // the exe stays locked until the process is gone
		if err := os.RemoveAll(helperDir()); err == nil {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	return removeGrant(sid)
}

// removeGrant takes away the write access to the hosts file that earlier
// versions gave the user instead of installing the helper.
func removeGrant(sid string) error {
	out, err := hidden("icacls.exe", systemHostsPath(), "/remove:g", "*"+sid).CombinedOutput()
	if err != nil {
		return fmt.Errorf("icacls: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func stopService(s *mgr.Service) {
	st, err := s.Control(svc.Stop)
	for i := 0; err == nil && st.State != svc.Stopped && i < 100; i++ {
		time.Sleep(100 * time.Millisecond)
		st, err = s.Query()
	}
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// --- the service ------------------------------------------------------------------

type helperSvc struct {
	sid string
	mu  sync.Mutex // one hosts write at a time
}

func (h *helperSvc) Execute(_ []string, r <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	if !sidPattern.MatchString(h.sid) {
		return true, 1
	}
	first, err := h.newPipe(true)
	if err != nil {
		return true, 2
	}
	go h.serve(first)
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for c := range r {
		switch c.Cmd {
		case svc.Interrogate:
			status <- c.CurrentStatus
		case svc.Stop, svc.Shutdown:
			status <- svc.Status{State: svc.StopPending}
			return false, 0
		}
	}
	return false, 0
}

// newPipe creates one instance of the pipe, which serves one client. SYSTEM
// has full access and the installing user can read and write.
func (h *helperSvc) newPipe(first bool) (windows.Handle, error) {
	sd, err := windows.SecurityDescriptorFromString(fmt.Sprintf("D:P(A;;GA;;;SY)(A;;0x%x;;;%s)", pipeAccess, h.sid))
	if err != nil {
		return 0, err
	}
	sa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	name, _ := windows.UTF16PtrFromString(helperPipe)
	flags := uint32(windows.PIPE_ACCESS_DUPLEX)
	if first {
		flags |= windows.FILE_FLAG_FIRST_PIPE_INSTANCE // fail if someone else already serves this name
	}
	return windows.CreateNamedPipe(name, flags,
		windows.PIPE_TYPE_BYTE|windows.PIPE_READMODE_BYTE|windows.PIPE_WAIT|windows.PIPE_REJECT_REMOTE_CLIENTS,
		windows.PIPE_UNLIMITED_INSTANCES, 64<<10, 64<<10, 0, sa)
}

func (h *helperSvc) serve(p windows.Handle) {
	for {
		if err := windows.ConnectNamedPipe(p, nil); err != nil && err != windows.ERROR_PIPE_CONNECTED {
			windows.CloseHandle(p)
		} else {
			go h.handle(p)
		}
		var err error
		for p, err = h.newPipe(false); err != nil; p, err = h.newPipe(false) {
			time.Sleep(time.Second)
		}
	}
}

const maxHosts = 4 << 20

func (h *helperSvc) handle(p windows.Handle) {
	f := os.NewFile(uintptr(p), helperPipe)
	defer f.Close()
	defer windows.DisconnectNamedPipe(p)
	defer windows.FlushFileBuffers(p)
	var req helperRequest
	var resp helperResponse
	if err := json.NewDecoder(io.LimitReader(f, maxHosts)).Decode(&req); err != nil {
		resp.Error = "bad request: " + err.Error()
	} else {
		resp = h.do(req)
	}
	json.NewEncoder(f).Encode(resp)
}

func (h *helperSvc) do(req helperRequest) helperResponse {
	switch req.Op {
	case "version":
		return helperResponse{Proto: helperProto}
	case "write":
		h.mu.Lock()
		defer h.mu.Unlock()
		if err := os.WriteFile(systemHostsPath(), []byte(req.Hosts), 0o644); err != nil {
			return helperResponse{Error: err.Error()}
		}
		hidden("ipconfig.exe", "/flushdns").Run()
		var addrs []netip.Addr
		for _, s := range req.Drop {
			if a, err := netip.ParseAddr(s); err == nil {
				addrs = append(addrs, a)
			}
		}
		n, err := closeConnections(addrs)
		if err != nil {
			return helperResponse{Closed: n, Error: "hosts written, but closing connections failed: " + err.Error()}
		}
		return helperResponse{Proto: helperProto, Closed: n}
	}
	return helperResponse{Error: "unknown request " + req.Op}
}

// --- closing connections --------------------------------------------------------

var (
	iphlpapi        = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetTcpTable = iphlpapi.NewProc("GetTcpTable")
	procSetTcpEntry = iphlpapi.NewProc("SetTcpEntry")
)

// tcpRow is MIB_TCPROW. Addresses and ports are in network byte order.
type tcpRow struct{ State, LocalAddr, LocalPort, RemoteAddr, RemotePort uint32 }

const (
	tcpStateEstablished = 5
	tcpStateDeleteTCB   = 12
)

// closeConnections resets established connections to port 80 or 443 on the
// given addresses, whichever program holds them. Browsers then connect again
// and look the hostname up again, instead of reusing a keep-alive connection
// to where it used to point. Windows can only do this for IPv4, and only as
// admin.
func closeConnections(addrs []netip.Addr) (int, error) {
	want := map[uint32]bool{}
	for _, a := range addrs {
		if a.Is4() {
			b := a.As4()
			want[binary.LittleEndian.Uint32(b[:])] = true
		}
	}
	if len(want) == 0 {
		return 0, nil
	}
	var buf []byte
	size := uint32(0)
	for {
		var p *byte
		if len(buf) > 0 {
			p = &buf[0]
		}
		r, _, _ := procGetTcpTable.Call(uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&size)), 0)
		if syscall.Errno(r) == windows.ERROR_INSUFFICIENT_BUFFER {
			buf = make([]byte, size)
			continue
		}
		if r != 0 {
			return 0, fmt.Errorf("GetTcpTable: %w", syscall.Errno(r))
		}
		break
	}
	if len(buf) < 4 {
		return 0, nil
	}
	rows := unsafe.Slice((*tcpRow)(unsafe.Pointer(&buf[4])), binary.LittleEndian.Uint32(buf))
	closed := 0
	var firstErr error
	for _, row := range rows {
		port := uint16(row.RemotePort>>8&0xff | row.RemotePort&0xff<<8)
		if row.State != tcpStateEstablished || !want[row.RemoteAddr] || (port != 80 && port != 443) {
			continue
		}
		row.State = tcpStateDeleteTCB
		if r, _, _ := procSetTcpEntry.Call(uintptr(unsafe.Pointer(&row))); r != 0 {
			if firstErr == nil {
				firstErr = fmt.Errorf("SetTcpEntry: %w", syscall.Errno(r))
			}
			continue
		}
		closed++
	}
	return closed, firstErr
}
