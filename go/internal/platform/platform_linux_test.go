package platform

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoginItem(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	if LoginItemEnabled() {
		t.Fatal("enabled before setting")
	}
	if err := SetLoginItem(true); err != nil || !LoginItemEnabled() {
		t.Fatalf("enable: %v", err)
	}
	b, _ := os.ReadFile(autostartPath())
	if !strings.Contains(string(b), "Exec=\""+executable()+"\"") {
		t.Fatalf("desktop file:\n%s", b)
	}
	if err := SetLoginItem(false); err != nil || LoginItemEnabled() {
		t.Fatalf("disable: %v", err)
	}
}

func TestWritableAndDirectWrite(t *testing.T) {
	p := filepath.Join(t.TempDir(), "hosts")
	os.WriteFile(p, []byte("a"), 0o644)
	if !Writable(p) {
		t.Fatal("own file not writable")
	}
	if elevated, err := ElevatedWrite(p, []byte("b")); err != nil || elevated {
		t.Fatalf("direct write: %v %v", err, elevated)
	}
	if os.Getuid() != 0 && Writable("/etc/shadow") {
		t.Fatal("/etc/shadow writable")
	}
	if HostsPath() != "/etc/hosts" && os.Getenv("HOSTS_PATH") == "" {
		t.Fatal(HostsPath())
	}
	if !strings.Contains(TrustCommand("/x.crt"), "update-ca-certificates") {
		t.Fatal("trust command")
	}
}
