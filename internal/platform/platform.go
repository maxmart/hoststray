// Package platform wraps the OS-specific bits: privilege elevation, trusting
// the CA, dialogs, launch at login, opening URLs and the clipboard.
package platform

import (
	"errors"
	"log"
	"net/netip"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
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

// HostsPasswordless reports whether hosts writes work without a password or
// UAC prompt: through the helper service, or because the user may write the
// file.
func HostsPasswordless(path string) bool { return helperReady(path) || Writable(path) }

// WriteHosts writes the hosts file through the helper service if there is
// one, or else like ElevatedWrite. Where it can (the helper, or a UAC prompt
// on Windows) it then closes connections to the addresses in drop, so
// browsers stop reusing keep-alive connections to where a hostname used to
// point.
func WriteHosts(path string, content []byte, drop []netip.Addr) (elevated bool, err error) {
	if err := helperWrite(path, content, drop); err == nil {
		return false, nil
	} else if !errors.Is(err, errNoHelper) {
		log.Printf("%v; writing without it", err)
	}
	return elevatedWrite(path, content, drop)
}

// HelperSetGroup switches a hosts file group through the helper. handled is
// false when there is no helper (or it can't do it); then write the file
// yourself, which may prompt.
func HelperSetGroup(path, name string, enable bool) (handled bool, err error) {
	return helperSetGroup(path, name, enable)
}

// HelperReady reports whether the helper is installed and answering for
// path, so group switches skip the prompt and reset stale connections.
func HelperReady(path string) bool { return helperReady(path) }

// SetHelper installs or removes the helper. It prompts for elevation itself.
func SetHelper(enable bool) error { return setHelper(enable) }

// HelperOutdated reports whether the installed helper isn't the one this
// version of the app ships, so it should be installed again.
func HelperOutdated() bool { return helperOutdated() }

// HelperCommand runs the command line modes of the helper service (running
// it, installing it, and the like). ok is false for any other command line.
func HelperCommand(args []string) (code int, ok bool) { return helperCommand(args) }

// ElevatedWrite writes content to path, first directly and, if that's not
// permitted, through an elevated copy (password or UAC prompt).
func ElevatedWrite(path string, content []byte) (elevated bool, err error) {
	return elevatedWrite(path, content, nil)
}

func elevatedWrite(path string, content []byte, drop []netip.Addr) (elevated bool, err error) {
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
	return true, elevatedCopy(tmp.Name(), path, drop)
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
// On Windows a build without the common-controls manifest can only offer the
// first two.
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

// IsSystemHosts reports whether path is the system's hosts file rather than
// a test copy.
func IsSystemHosts(path string) bool {
	return strings.EqualFold(filepath.Clean(path), systemHostsPath())
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
