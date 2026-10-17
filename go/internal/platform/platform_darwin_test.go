package platform

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoginItem(t *testing.T) {
	t.Setenv("HOME", t.TempDir()) // keep the real ~/Library/LaunchAgents untouched
	if LoginItemEnabled() {
		t.Fatal("enabled before setting")
	}
	if err := SetLoginItem(true); err != nil {
		t.Fatal(err)
	}
	if !LoginItemEnabled() {
		t.Fatal("not enabled")
	}
	if out, err := exec.Command("plutil", "-lint", launchAgentPath()).CombinedOutput(); err != nil {
		t.Fatalf("invalid plist: %s", out)
	}
	b, _ := os.ReadFile(launchAgentPath())
	if !strings.Contains(string(b), executable()) || !strings.Contains(string(b), "<key>RunAtLoad</key>") {
		t.Fatalf("plist:\n%s", b)
	}
	if err := SetLoginItem(false); err != nil || LoginItemEnabled() {
		t.Fatalf("disable: %v", err)
	}
	if err := SetLoginItem(false); err != nil {
		t.Fatalf("disabling twice: %v", err)
	}
}

func TestWritableAndDirectWrite(t *testing.T) {
	p := filepath.Join(t.TempDir(), "hosts")
	os.WriteFile(p, []byte("a"), 0o644)
	if !Writable(p) {
		t.Fatal("own file not writable")
	}
	if b, _ := os.ReadFile(p); string(b) != "a" {
		t.Fatal("Writable modified the file")
	}
	elevated, err := ElevatedWrite(p, []byte("b"))
	if err != nil || elevated {
		t.Fatalf("direct write: %v elevated=%v", err, elevated)
	}
	if b, _ := os.ReadFile(p); string(b) != "b" {
		t.Fatal("not written")
	}
	if Writable("/etc/shells") {
		t.Fatal("root-only file reported writable")
	}
	if Writable(filepath.Join(t.TempDir(), "missing")) {
		t.Fatal("missing file reported writable")
	}
}

func TestHostsPath(t *testing.T) {
	t.Setenv("HOSTS_PATH", "")
	if HostsPath() != "/etc/hosts" {
		t.Fatal(HostsPath())
	}
	t.Setenv("HOSTS_PATH", "/tmp/x")
	if HostsPath() != "/tmp/x" {
		t.Fatal(HostsPath())
	}
}

// TestAskButtons clicks real dialog buttons via accessibility scripting.
// Opt-in, since it puts dialogs on screen: HOSTSTRAY_UI_TESTS=1.
func TestAskButtons(t *testing.T) {
	if os.Getenv("HOSTSTRAY_UI_TESTS") == "" {
		t.Skip("set HOSTSTRAY_UI_TESTS=1 to run")
	}
	buttons := []string{"Allow", "Not now", "Don't ask again"}
	for want, label := range buttons {
		got := make(chan int)
		go func() { got <- Ask("Hosts Tray test", "Automated test, please ignore.", buttons...) }()
		time.Sleep(1500 * time.Millisecond)
		out, err := exec.Command("osascript", "-e", `tell application "System Events" to tell process "osascript" to click button "`+label+`" of window 1`).CombinedOutput()
		if err != nil {
			t.Fatalf("click %q: %v %s", label, err, out)
		}
		if g := <-got; g != want {
			t.Errorf("clicked %q, got index %d", label, g)
		}
	}
	// Killing the dialog counts as dismissed, not as any button.
	got := make(chan int)
	go func() { got <- Ask("Hosts Tray test", "Automated test, please ignore.", buttons...) }()
	time.Sleep(1500 * time.Millisecond)
	exec.Command("pkill", "-f", "Automated test, please ignore").Run()
	if g := <-got; g != -1 {
		t.Errorf("dismissed dialog returned %d", g)
	}
}
