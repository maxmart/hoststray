package platform

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows/registry"
)

func TestLoginItem(t *testing.T) {
	SetLoginItem(false)
	if LoginItemEnabled() {
		t.Fatal("enabled before setting")
	}
	if err := SetLoginItem(true); err != nil || !LoginItemEnabled() {
		t.Fatalf("enable: %v", err)
	}
	k, _ := registry.OpenKey(registry.CURRENT_USER, runKey, registry.QUERY_VALUE)
	v, _, _ := k.GetStringValue(runValue)
	k.Close()
	if v != `"`+executable()+`"` {
		t.Fatalf("Run value %q", v)
	}
	if err := SetLoginItem(false); err != nil || LoginItemEnabled() {
		t.Fatalf("disable: %v", err)
	}
	if err := SetLoginItem(false); err != nil {
		t.Fatalf("disable twice: %v", err)
	}
}

func TestWritableAndDirectWrite(t *testing.T) {
	p := filepath.Join(t.TempDir(), "hosts")
	os.WriteFile(p, []byte("a\r\n"), 0o644)
	if !Writable(p) {
		t.Fatal("own file not writable")
	}
	if elevated, err := ElevatedWrite(p, []byte("b\r\n")); err != nil || elevated {
		t.Fatalf("direct write: %v %v", err, elevated)
	}
	if b, _ := os.ReadFile(p); string(b) != "b\r\n" {
		t.Fatalf("content %q", b)
	}
	os.Chmod(p, 0o444) // read-only attribute
	if Writable(p) {
		t.Fatal("read-only file reported writable")
	}
}

func TestPaths(t *testing.T) {
	t.Setenv("HOSTS_PATH", "")
	if !strings.HasSuffix(strings.ToLower(HostsPath()), `\system32\drivers\etc\hosts`) {
		t.Fatal(HostsPath())
	}
	if !strings.HasSuffix(DataDir(), `\hoststray`) {
		t.Fatal(DataDir())
	}
	if !strings.Contains(TrustCommand(`C:\x.crt`), "certutil -user -addstore Root") {
		t.Fatal("trust command")
	}
}
