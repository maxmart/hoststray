package helper

import (
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/maxmart/hoststray/internal/hosts"
)

const testHosts = `127.0.0.1	localhost

#==== dev
#127.0.0.1	app.example.test
#====
`

// TestServer runs the daemon's server as the current user, on a socket in a
// temp folder, and talks to it like the app does.
func TestServer(t *testing.T) {
	dir := t.TempDir()
	hostsFile := filepath.Join(dir, "hosts")
	os.WriteFile(hostsFile, []byte(testHosts), 0o644)
	sock := filepath.Join(dir, "s")
	oldSock, oldUID := Socket, serverUID
	Socket, serverUID = sock, uint32(os.Getuid())
	t.Cleanup(func() { Socket, serverUID = oldSock, oldUID })

	if Running() {
		t.Fatal("running before it was started")
	}
	l, err := listen(sock, os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	if fi, err := os.Stat(sock); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode: %v %v", fi.Mode(), err)
	}
	var blocked []netip.Addr
	s := &server{uid: uint32(os.Getuid()), hosts: hostsFile, conns: make(chan struct{}, maxConns),
		block: func(a []netip.Addr) { blocked = a },
		lookup: func(old, next *hosts.Doc) []netip.Addr {
			// Where app.example.test pointed before: a real server, and loopback.
			return []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("127.0.0.1")}
		}}
	go s.serve(l)

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
	if fi, _ := os.Stat(hostsFile); fi.Mode().Perm() != 0o644 {
		t.Fatalf("hosts mode %v", fi.Mode())
	}
	if len(blocked) != 1 || blocked[0].String() != "192.0.2.1" {
		t.Fatalf("blocked %v", blocked)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".hosts-*")); len(left) > 0 {
		t.Fatalf("temp files left: %v", left)
	}
	if _, err := Call(Request{Op: "group", Group: "nope", Enable: true}); !errors.Is(err, ErrNoGroup) {
		t.Fatalf("missing group: %v", err)
	}
	// Whole-file writes are gone.
	if _, err := Call(Request{Op: "write"}); err == nil {
		t.Fatal("write accepted")
	}

	// Another user is turned away.
	s.uid++
	if _, err := Call(Request{Op: "version"}); err == nil || err.Error() != "not allowed" {
		t.Fatalf("other user: %v", err)
	}
	// And the app won't talk to a socket served by the wrong user.
	serverUID = 0
	if _, err := Call(Request{Op: "version"}); err == nil || !strings.Contains(err.Error(), "isn't served by the helper") {
		t.Fatalf("wrong server: %v", err)
	}
}

func TestStaleRules(t *testing.T) {
	rules := StaleRules([]netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")})
	f := filepath.Join(t.TempDir(), "rules")
	os.WriteFile(f, []byte(rules), 0o644)
	out, err := exec.Command(Pfctl, "-nvf", f).CombinedOutput() // parse only; no root needed
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	for _, want := range []string{
		"pass out quick inet proto tcp from any to 192.0.2.1 port = 443 flags S/SA keep state",
		"block return out quick inet6 proto tcp from any to 2001:db8::1 port = 80",
	} {
		if !strings.Contains(string(out), want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestPromptScript(t *testing.T) {
	if s := PromptScript([]netip.Addr{netip.MustParseAddr("127.0.0.1")}); s != "" {
		t.Fatalf("loopback only: %q", s)
	}
	s := PromptScript([]netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("::ffff:192.0.2.2")})
	if out, err := exec.Command("/bin/sh", "-n", "-c", s).CombinedOutput(); err != nil {
		t.Fatalf("shell syntax: %v %s\n%s", err, out, s)
	}
	for _, want := range []string{"-k 0.0.0.0/0 -k 192.0.2.2", "sleep 360;", "-X $t"} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in:\n%s", want, s)
		}
	}
}
