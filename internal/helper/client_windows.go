package helper

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// On Windows the daemon is a service running as SYSTEM. Its exe lives in
// Program Files, which only admins can change; the app's own folder is the
// user's. The app talks to it over a named pipe only the installing user can
// open.

const Service = "HostsTrayHelper"

// Pipe is the named pipe the service serves; tests change it.
var Pipe = `\\.\pipe\HostsTrayHelper`

const (
	// pipeAccess is read and write without FILE_CREATE_PIPE_INSTANCE, so
	// clients can't serve the pipe themselves.
	pipeAccess = windows.FILE_GENERIC_READ | windows.FILE_WRITE_DATA
)

// Dir holds the installed service exe and its log.
func Dir() string {
	pf := os.Getenv("ProgramFiles")
	if pf == "" {
		pf = `C:\Program Files`
	}
	return filepath.Join(pf, "Hosts Tray Helper")
}

func InstalledExe() string { return filepath.Join(Dir(), "hoststray-helper.exe") }

func logFile() string { return filepath.Join(Dir(), "helper.log") }

// servicePID returns the process ID of the running service.
func servicePID() (uint32, error) {
	m, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return 0, ErrNotRunning
	}
	defer windows.CloseServiceHandle(m)
	name, _ := windows.UTF16PtrFromString(Service)
	s, err := windows.OpenService(m, name, windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return 0, ErrNotRunning
	}
	defer windows.CloseServiceHandle(s)
	var st windows.SERVICE_STATUS_PROCESS
	var n uint32
	if err := windows.QueryServiceStatusEx(s, windows.SC_STATUS_PROCESS_INFO, (*byte)(unsafe.Pointer(&st)), uint32(unsafe.Sizeof(st)), &n); err != nil {
		return 0, ErrNotRunning
	}
	if st.CurrentState != windows.SERVICE_RUNNING {
		return 0, ErrNotRunning
	}
	return st.ProcessId, nil
}

// serverPID is who must serve the pipe; tests change it.
var serverPID = servicePID

// Call sends one request to the service.
func Call(req Request) (Response, error) {
	var resp Response
	pid, err := serverPID()
	if err != nil {
		return resp, err
	}
	name, _ := windows.UTF16PtrFromString(Pipe)
	var h windows.Handle
	for i := 0; ; i++ {
		h, err = windows.CreateFile(name, pipeAccess, 0, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OVERLAPPED, 0)
		if (err == windows.ERROR_PIPE_BUSY || err == windows.ERROR_FILE_NOT_FOUND) && i < 40 {
			time.Sleep(50 * time.Millisecond)
			continue
		}
		break
	}
	if err != nil {
		return resp, fmt.Errorf("hosts helper: %w", err)
	}
	// Only trust the service itself: anyone could have created a pipe by this
	// name while it wasn't running.
	var server uint32
	if err := windows.GetNamedPipeServerProcessId(h, &server); err != nil || server != pid {
		windows.CloseHandle(h)
		return resp, errors.New("hosts helper: the pipe isn't served by the helper service")
	}
	f := os.NewFile(uintptr(h), Pipe) // overlapped, so deadlines work
	defer f.Close()
	f.SetDeadline(time.Now().Add(15 * time.Second))
	if err := json.NewEncoder(f).Encode(req); err != nil {
		return resp, fmt.Errorf("hosts helper: %w", err)
	}
	if err := json.NewDecoder(f).Decode(&resp); err != nil {
		return resp, fmt.Errorf("hosts helper: %w", err)
	}
	if resp.NoGroup {
		return resp, fmt.Errorf("%w %q", ErrNoGroup, req.Group)
	}
	if resp.Error != "" {
		return resp, errors.New(resp.Error)
	}
	return resp, nil
}

// Running reports whether the service answers.
func Running() bool {
	_, err := Call(Request{Op: "version"})
	return err == nil
}

// Installed reports whether the service is installed, running or not.
func Installed() bool {
	m, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return false
	}
	defer windows.CloseServiceHandle(m)
	name, _ := windows.UTF16PtrFromString(Service)
	s, err := windows.OpenService(m, name, windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return false
	}
	windows.CloseServiceHandle(s)
	return true
}

// DiffersFrom reports whether the installed service exe isn't bundled (the
// copy the app carries), as after an app update.
func DiffersFrom(bundled []byte) bool {
	f, err := os.Open(InstalledExe())
	if err != nil {
		return false
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return false
	}
	want := sha256.Sum256(bundled)
	return !bytes.Equal(h.Sum(nil), want[:])
}
