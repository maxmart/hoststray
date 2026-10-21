package helper

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"github.com/maxmart/hoststray/internal/hosts"
)

const testHosts = "127.0.0.1\tlocalhost\r\n\r\n#==== dev\r\n#127.0.0.1\tapp.example.test\r\n#====\r\n"

// TestServer runs the service's pipe server in the test process, on a
// test pipe, and talks to it like the app does.
func TestServer(t *testing.T) {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sid := u.User.Sid.String()
	dir := t.TempDir()
	hostsFile := filepath.Join(dir, "hosts")
	os.WriteFile(hostsFile, []byte(testHosts), 0o644)
	oldPipe := Pipe
	Pipe = fmt.Sprintf(`\\.\pipe\HostsTrayHelper-test-%d`, os.Getpid())
	serverPID = func() (uint32, error) { return uint32(os.Getpid()), nil }
	t.Cleanup(func() { serverPID, Pipe = servicePID, oldPipe })

	var mu sync.Mutex
	var blocked []netip.Addr
	s := newServer(sid, hostsFile)
	s.owner = sid // so the test can make more pipe instances
	s.block = func(a []netip.Addr) { mu.Lock(); blocked = a; mu.Unlock() }
	s.lookup = func(old, next *hosts.Doc) []netip.Addr {
		// Where app.example.test pointed before: a real server, and loopback.
		return []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("127.0.0.1")}
	}
	p, err := s.newPipe(true)
	if err != nil {
		t.Fatal(err)
	}
	go s.serve(p)
	name, _ := windows.UTF16PtrFromString(Pipe)

	resp, err := Call(Request{Op: "version"})
	if err != nil || resp.Proto != Proto {
		t.Fatalf("version: %+v %v", resp, err)
	}
	if _, err := Call(Request{Op: "group", Group: "dev", Enable: true}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(hostsFile)
	if doc := hosts.Parse(string(b)); hosts.Active(doc)["app.example.test"] != "127.0.0.1" || !hosts.Groups(doc)[0].Enabled {
		t.Fatalf("hosts after enabling:\n%s", b)
	}
	if !strings.Contains(string(b), "\r\n") {
		t.Fatal("line endings changed")
	}
	mu.Lock()
	if len(blocked) != 1 || blocked[0].String() != "192.0.2.1" {
		t.Fatalf("blocked %v", blocked)
	}
	mu.Unlock()
	if left, _ := filepath.Glob(filepath.Join(dir, ".hosts-*")); len(left) > 0 {
		t.Fatalf("temp files left: %v", left)
	}
	if _, err := Call(Request{Op: "group", Group: "nope", Enable: true}); !errors.Is(err, ErrNoGroup) {
		t.Fatalf("missing group: %v", err)
	}
	if _, err := Call(Request{Op: "write"}); err == nil {
		t.Fatal("write accepted")
	}

	// Several clients at once are all answered.
	var wg sync.WaitGroup
	errs := make(chan error, 10)
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := Call(Request{Op: "version"}); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent: %v", err)
	}

	// A client that sends nothing is cut off, and doesn't hold up others.
	idle, err := windows.CreateFile(name, pipeAccess, 0, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(idle)
	start := time.Now()
	if _, err := Call(Request{Op: "version"}); err != nil || time.Since(start) > 2*time.Second {
		t.Fatalf("with an idle client: %v after %v", err, time.Since(start))
	}

	// Too large a request is refused.
	f := openRaw(t)
	big := Request{Op: "group", Group: strings.Repeat("x", maxReq)}
	json.NewEncoder(f).Encode(big)
	var r Response
	if err := json.NewDecoder(f).Decode(&r); err != nil || !strings.HasPrefix(r.Error, "bad request") {
		t.Fatalf("big request: %+v %v", r, err)
	}
	f.Close()

	// And the app won't talk to a pipe served by anyone else.
	serverPID = func() (uint32, error) { return uint32(os.Getpid()) + 1, nil }
	if _, err := Call(Request{Op: "version"}); err == nil || !strings.Contains(err.Error(), "isn't served by the helper") {
		t.Fatalf("wrong server: %v", err)
	}
}

// The user may read and write the pipe, but not serve it: asking for
// GENERIC_WRITE includes that right, and is refused.
func TestPipeAccess(t *testing.T) {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	oldPipe := Pipe
	Pipe = fmt.Sprintf(`\\.\pipe\HostsTrayHelper-access-%d`, os.Getpid())
	t.Cleanup(func() { Pipe = oldPipe })
	p, err := newServer(u.User.Sid.String(), "").newPipe(true)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(p)
	name, _ := windows.UTF16PtrFromString(Pipe)
	if c, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, 0, 0); err == nil {
		windows.CloseHandle(c)
		t.Fatal("opened with GENERIC_WRITE")
	}
	c, err := windows.CreateFile(name, pipeAccess, 0, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	windows.CloseHandle(c)
}

func openRaw(t *testing.T) *os.File {
	name, _ := windows.UTF16PtrFromString(Pipe)
	h, err := windows.CreateFile(name, pipeAccess, 0, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OVERLAPPED, 0)
	if err != nil {
		t.Fatal(err)
	}
	f := os.NewFile(uintptr(h), Pipe)
	f.SetDeadline(time.Now().Add(5 * time.Second))
	return f
}

func TestValidSID(t *testing.T) {
	for sid, ok := range map[string]bool{
		"S-1-5-21-2253417443-204052995-1260948420-1001": true,
		"S-1-12-1-1-2-3-4": true,
		"S-1-5-18":         false, // SYSTEM
		"S-1-5-21-1-2-3-4)(A;;GA;;;WD": false,
	} {
		if ValidSID(sid) != ok {
			t.Errorf("%s: %v", sid, !ok)
		}
	}
}
