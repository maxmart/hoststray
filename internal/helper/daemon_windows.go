package helper

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"

	"github.com/maxmart/hoststray/internal/hosts"
)

const (
	maxConns = 4 // at once; more wait
	maxReq   = 64 << 10
)

var procDnsFlushResolverCache = windows.NewLazySystemDLL("dnsapi.dll").NewProc("DnsFlushResolverCache")

func hostsPath() string {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	return filepath.Join(root, "System32", "drivers", "etc", "hosts")
}

type server struct {
	sid    string // the user allowed to open the pipe
	owner  string // who serves it: SYSTEM, or the user in tests
	hosts  string
	mu     sync.Mutex // one hosts change at a time
	conns  chan struct{}
	block  func([]netip.Addr)                      // resets stale connections; CloseConnections unless testing
	lookup func(old, next *hosts.Doc) []netip.Addr // hosts.MovedAway unless testing
}

func newServer(sid, hostsFile string) *server {
	return &server{sid: sid, owner: "SY", hosts: hostsFile, conns: make(chan struct{}, maxConns), lookup: hosts.MovedAway,
		block: func(addrs []netip.Addr) {
			if _, err := CloseConnections(addrs); err != nil {
				log.Print(err)
			}
		}}
}

// RunService is the service: it serves sid until the app at appExe is gone.
func RunService(sid, appExe string) error {
	if !ValidSID(sid) {
		return fmt.Errorf("bad user SID %q", sid)
	}
	if f, err := openLog(); err == nil {
		log.SetOutput(f)
	}
	return svc.Run(Service, &service{s: newServer(sid, hostsPath()), appExe: appExe})
}

// openLog appends to the log next to the exe, which only admins can change,
// starting afresh past 1 MB.
func openLog() (*os.File, error) {
	if fi, err := os.Stat(logFile()); err == nil && fi.Size() > 1<<20 {
		os.Rename(logFile(), logFile()+".1")
	}
	return os.OpenFile(logFile(), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
}

type service struct {
	s      *server
	appExe string
}

func (h *service) Execute(_ []string, r <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	first, err := h.s.newPipe(true)
	if err != nil {
		log.Printf("pipe: %v", err)
		return true, 2
	}
	go h.s.serve(first)
	gone := make(chan struct{})
	go func() {
		watchApp(h.appExe)
		close(gone)
	}()
	log.Printf("helper (proto %d) serving %s for %s", Proto, h.s.sid, h.appExe)
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case <-gone:
			log.Printf("%s is gone; uninstalling", h.appExe)
			if err := uninstallSelf(h.s.sid); err != nil {
				log.Printf("uninstall: %v", err)
			}
			return false, 0
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				return false, 0
			}
		}
	}
}

// newPipe creates one instance of the pipe, which serves one client. The
// owner (SYSTEM) has full access, which includes making more instances; the
// installing user can read and write.
func (s *server) newPipe(first bool) (windows.Handle, error) {
	sd, err := windows.SecurityDescriptorFromString(fmt.Sprintf("D:P(A;;GA;;;%s)(A;;0x%x;;;%s)", s.owner, pipeAccess, s.sid))
	if err != nil {
		return 0, err
	}
	sa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	name, _ := windows.UTF16PtrFromString(Pipe)
	flags := uint32(windows.PIPE_ACCESS_DUPLEX | windows.FILE_FLAG_OVERLAPPED)
	if first {
		flags |= windows.FILE_FLAG_FIRST_PIPE_INSTANCE // fail if someone else already serves this name
	}
	return windows.CreateNamedPipe(name, flags,
		windows.PIPE_TYPE_BYTE|windows.PIPE_READMODE_BYTE|windows.PIPE_WAIT|windows.PIPE_REJECT_REMOTE_CLIENTS,
		windows.PIPE_UNLIMITED_INSTANCES, 64<<10, 64<<10, 0, sa)
}

// connect waits for a client on pipe instance p.
func connect(p windows.Handle) error {
	ev, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(ev)
	ov := windows.Overlapped{HEvent: ev}
	switch err := windows.ConnectNamedPipe(p, &ov); err {
	case nil, windows.ERROR_PIPE_CONNECTED:
		return nil
	case windows.ERROR_IO_PENDING:
		if _, err := windows.WaitForSingleObject(ev, windows.INFINITE); err != nil {
			return err
		}
		var n uint32
		return windows.GetOverlappedResult(p, &ov, &n, false)
	default:
		return err
	}
}

func (s *server) serve(p windows.Handle) {
	for {
		if err := connect(p); err != nil {
			windows.CloseHandle(p)
		} else {
			s.conns <- struct{}{}
			go func(p windows.Handle) {
				defer func() { <-s.conns }()
				s.handle(p)
			}(p)
		}
		var err error
		for p, err = s.newPipe(false); err != nil; p, err = s.newPipe(false) {
			time.Sleep(time.Second)
		}
	}
}

func (s *server) handle(p windows.Handle) {
	f := os.NewFile(uintptr(p), Pipe) // overlapped, so deadlines work
	defer f.Close()
	defer windows.DisconnectNamedPipe(p)
	defer windows.FlushFileBuffers(p)
	f.SetDeadline(time.Now().Add(15 * time.Second))
	var req Request
	var resp Response
	if err := json.NewDecoder(io.LimitReader(f, maxReq)).Decode(&req); err != nil {
		resp.Error = "bad request: " + err.Error()
	} else {
		resp = s.do(req)
	}
	json.NewEncoder(f).Encode(resp)
}

func (s *server) do(req Request) Response {
	switch req.Op {
	case "version":
		return Response{Proto: Proto}
	case "group":
		s.mu.Lock()
		defer s.mu.Unlock()
		changed, err := s.setGroup(req.Group, req.Enable)
		if errors.Is(err, ErrNoGroup) {
			return Response{Proto: Proto, NoGroup: true}
		}
		if err != nil {
			log.Printf("group %q on=%v: %v", req.Group, req.Enable, err)
			return Response{Proto: Proto, Error: err.Error()}
		}
		log.Printf("group %q on=%v; dropping connections to %v", req.Group, req.Enable, changed)
		return Response{Proto: Proto}
	}
	return Response{Error: "unknown request " + req.Op}
}

// setGroup flips a group in the hosts file and returns the addresses whose
// connections it resets.
func (s *server) setGroup(name string, enable bool) ([]netip.Addr, error) {
	b, err := os.ReadFile(s.hosts)
	if err != nil {
		return nil, err
	}
	old, next := hosts.Parse(string(b)), hosts.Parse(string(b))
	if !hosts.SetGroup(next, name, enable) {
		return nil, ErrNoGroup
	}
	drop := Droppable(s.lookup(old, next)) // before the write: where names point now
	if err := writeAtomic(s.hosts, []byte(hosts.Serialize(next))); err != nil {
		return nil, err
	}
	procDnsFlushResolverCache.Call()
	if len(drop) > 0 {
		s.block(drop)
	}
	return drop, nil
}

// writeAtomic replaces path through a temp file in the same folder, so the
// hosts file is never seen half written. The temp file inherits the folder's
// permissions, as the hosts file does.
func writeAtomic(path string, content []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".hosts-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(content); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	from, _ := windows.UTF16PtrFromString(f.Name())
	to, _ := windows.UTF16PtrFromString(path)
	// Antivirus scanners open the hosts file whenever it changes; give them a
	// moment.
	for i := 0; ; i++ {
		err = windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
		if err == nil || i == 20 {
			return err
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// watchApp returns once the app is gone (uninstalled without its
// uninstaller, or deleted). An update renames the exe for a moment, so only a
// miss that lasts a minute counts.
func watchApp(appExe string) {
	missing := false
	for {
		_, err := os.Stat(appExe)
		gone := errors.Is(err, os.ErrNotExist)
		if gone && missing {
			return
		}
		missing = gone
		if gone {
			time.Sleep(time.Minute)
		} else {
			time.Sleep(10 * time.Minute)
		}
	}
}
