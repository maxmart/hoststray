// Package platform wraps the OS-specific bits: privilege elevation, trusting
// the CA, dialogs, launch at login, opening URLs and the clipboard.
package platform

import (
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
)

// ErrCancelled is returned when the user dismisses a password/UAC prompt.
var ErrCancelled = errors.New("cancelled by user")

// DataDir is where settings, proxy.conf and certificates live. It matches the
// Electron version's userData folder so existing setups carry over.
func DataDir() string {
	if d := os.Getenv("HOSTSTRAY_DATA_DIR"); d != "" {
		return d
	}
	base, err := os.UserConfigDir()
	if err != nil {
		base = os.TempDir()
	}
	return filepath.Join(base, "hoststray")
}

// Writable reports whether the current user can write path without elevation.
// It opens the file for writing without truncating, so nothing changes.
func Writable(path string) bool {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return false
	}
	f.Close()
	return true
}

// plainUser matches account names that are safe to put into an elevated shell
// command (optionally DOMAIN\name on Windows).
var plainUser = regexp.MustCompile(`^([A-Za-z0-9._ -]+\\)?[A-Za-z0-9._-]+$`)

func currentUser() (string, error) {
	u, err := user.Current()
	if err != nil {
		return "", err
	}
	if !plainUser.MatchString(u.Username) {
		return "", errors.New("unsupported account name " + u.Username)
	}
	return u.Username, nil
}

// ElevatedWrite writes content to path, first directly and, if that's not
// permitted, through an elevated copy (password or UAC prompt).
func ElevatedWrite(path string, content []byte) (elevated bool, err error) {
	if err := os.WriteFile(path, content, 0o644); err == nil {
		return false, nil
	} else if !errors.Is(err, os.ErrPermission) {
		return false, err
	}
	tmp, err := os.CreateTemp("", "hoststray-hosts-*.tmp")
	if err != nil {
		return false, err
	}
	defer os.Remove(tmp.Name())
	// CreateTemp makes the file 0600, and cp carries that over to a hosts file
	// it creates, which would leave it readable by root only.
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return false, err
	}
	if _, err := tmp.Write(content); err != nil {
		tmp.Close()
		return false, err
	}
	tmp.Close()
	return true, elevatedCopy(tmp.Name(), path)
}

// SetUserWritable grants (or revokes) the current user write access to path,
// so later writes don't need elevation. It prompts for elevation itself.
func SetUserWritable(path string, enable bool) error { return setUserWritable(path, enable) }

// TrustCA adds the CA certificate to the current user's trust store. The OS
// shows its own confirmation or password prompt.
func TrustCA(certPath string) error { return trustCA(certPath) }

// TrustCommand is the command a user can run to trust the CA by hand.
func TrustCommand(certPath string) string { return trustCommand(certPath) }

// Ask shows a dialog with up to three buttons and returns the index of the
// one clicked (the first button is the default), or -1 if it was dismissed.
// Windows can only offer the first two choices.
func Ask(title, message string, buttons ...string) int { return ask(title, message, buttons) }

// Alert shows an informational or error message.
func Alert(title, message string) { ask(title, message, []string{"OK"}) }

func OpenURL(url string) error { return openURL(url) }

func CopyToClipboard(text string) error { return copyToClipboard(text) }

func LoginItemEnabled() bool { return loginItemEnabled() }

func SetLoginItem(enable bool) error { return setLoginItem(enable) }

func HostsPath() string {
	if p := os.Getenv("HOSTS_PATH"); p != "" {
		return p
	}
	return systemHostsPath()
}

func executable() string {
	exe, err := os.Executable()
	if err != nil {
		return os.Args[0]
	}
	if p, err := filepath.EvalSymlinks(exe); err == nil {
		return p
	}
	return exe
}
