package platform

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func systemHostsPath() string { return "/etc/hosts" }

func elevatedCopy(src, dst string) error {
	err := exec.Command("pkexec", "/bin/cp", src, dst).Run()
	if ee, ok := err.(*exec.ExitError); ok && ee.ExitCode() == 126 {
		return ErrCancelled
	}
	return err
}

func setUserWritable(path string, enable bool) error {
	name, err := currentUser()
	if err != nil {
		return err
	}
	if enable {
		return exec.Command("pkexec", "setfacl", "-m", "u:"+name+":rw", path).Run()
	}
	return exec.Command("pkexec", "setfacl", "-x", "u:"+name, path).Run()
}

func trustCA(certPath string) error {
	return errors.New("automatic trust isn't supported on Linux; run: " + trustCommand(certPath))
}

func trustCommand(certPath string) string {
	return fmt.Sprintf(`sudo cp "%s" /usr/local/share/ca-certificates/hoststray.crt && sudo update-ca-certificates`, certPath)
}

// ask uses zenity when available; otherwise it logs and picks the default.
func ask(title, message string, buttons []string) int {
	if _, err := exec.LookPath("zenity"); err != nil || len(buttons) == 0 {
		fmt.Fprintf(os.Stderr, "%s: %s\n", title, message)
		return 0
	}
	if len(buttons) == 1 {
		exec.Command("zenity", "--info", "--title", title, "--text", message).Run()
		return 0
	}
	args := []string{"--question", "--title", title, "--text", message, "--ok-label", buttons[0], "--cancel-label", buttons[len(buttons)-1]}
	for _, b := range buttons[1 : len(buttons)-1] {
		args = append(args, "--extra-button", b)
	}
	out, err := exec.Command("zenity", args...).Output()
	if err == nil {
		return 0
	}
	choice := strings.TrimSpace(string(out))
	for i, b := range buttons {
		if b == choice {
			return i
		}
	}
	if choice == "" {
		return len(buttons) - 1 // the cancel-labelled button
	}
	return -1
}

func openURL(url string) error { return exec.Command("xdg-open", url).Start() }

func copyToClipboard(text string) error {
	for _, c := range [][]string{{"wl-copy"}, {"xclip", "-selection", "clipboard"}, {"xsel", "--clipboard", "--input"}} {
		if _, err := exec.LookPath(c[0]); err == nil {
			cmd := exec.Command(c[0], c[1:]...)
			cmd.Stdin = strings.NewReader(text)
			return cmd.Run()
		}
	}
	return errors.New("no clipboard tool found")
}

func autostartPath() string {
	dir, _ := os.UserConfigDir()
	return filepath.Join(dir, "autostart", "hoststray.desktop")
}

func loginItemEnabled() bool {
	b, err := os.ReadFile(autostartPath())
	return err == nil && strings.Contains(string(b), executable())
}

func setLoginItem(enable bool) error {
	if !enable {
		if err := os.Remove(autostartPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	os.MkdirAll(filepath.Dir(autostartPath()), 0o755)
	desktop := "[Desktop Entry]\nType=Application\nName=Hosts Tray\nExec=\"" + executable() + "\"\nX-GNOME-Autostart-enabled=true\n"
	return os.WriteFile(autostartPath(), []byte(desktop), 0o644)
}
