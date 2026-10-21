package helper

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// These run as root, from the admin password prompt.

var plainUser = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// LookupUID checks that uid is a regular user's and returns their name.
func LookupUID(uid string) (uint32, string, error) {
	n, err := strconv.ParseUint(uid, 10, 32)
	if err != nil || n == 0 {
		return 0, "", fmt.Errorf("bad user id %q", uid)
	}
	u, err := user.LookupId(uid)
	if err != nil {
		return 0, "", err
	}
	if !plainUser.MatchString(u.Username) {
		return 0, "", errors.New("unsupported account name " + u.Username)
	}
	return uint32(n), u.Username, nil
}

// Install copies the running binary to InstalledExe and starts it as a
// daemon serving uid for as long as appExe exists.
func Install(uid, appExe string) error {
	n, name, err := LookupUID(uid)
	if err != nil {
		return err
	}
	if !filepath.IsAbs(appExe) || strings.ContainsAny(appExe, "<>&") {
		return fmt.Errorf("bad app path %q", appExe)
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	launchctl("bootout", "system/"+Label) // an older copy, if any
	if err := os.MkdirAll(filepath.Dir(InstalledExe), 0o755); err != nil {
		return err
	}
	// Copy to a new file and rename it into place, so a running copy is never
	// written to.
	tmp := InstalledExe + ".new"
	if err := copyFile(self, tmp, 0o755); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, InstalledExe); err != nil {
		os.Remove(tmp)
		return err
	}
	plist := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>` + Label + `</string>
	<key>ProgramArguments</key>
	<array>
		<string>` + InstalledExe + `</string>
		<string>--run</string>
		<string>` + strconv.Itoa(int(n)) + `</string>
		<string>` + appExe + `</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>StandardErrorPath</key>
	<string>` + LogFile + `</string>
</dict>
</plist>
`
	if err := os.WriteFile(Plist, []byte(plist), 0o644); err != nil {
		return err
	}
	if err := launchctl("bootstrap", "system", Plist); err != nil {
		return err
	}
	for i := 0; i < 50 && !Running(); i++ {
		time.Sleep(100 * time.Millisecond)
	}
	// The helper replaces the old way of skipping the prompt.
	return removeGrant(name)
}

// Uninstall stops and removes the daemon. Run from the daemon itself, it
// doesn't return: launchd stops it.
func Uninstall(uid uint32) error {
	_, name, err := LookupUID(strconv.Itoa(int(uid)))
	if err != nil {
		return err
	}
	(&pf{}).recover()
	for _, p := range []string{Plist, InstalledExe, Socket} {
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if err := removeGrant(name); err != nil {
		return err
	}
	launchctl("bootout", "system/"+Label)
	return nil
}

// removeGrant takes away the write access to the hosts file that earlier
// versions gave the user instead of installing the helper.
func removeGrant(name string) error {
	out, err := exec.Command("/bin/chmod", "-a", "user:"+name+" allow write,append", hostsPath).CombinedOutput()
	if err != nil && !strings.Contains(string(out), "No ACL present") {
		return fmt.Errorf("chmod: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func launchctl(args ...string) error {
	out, err := exec.Command("/bin/launchctl", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("launchctl %s: %v: %s", args[0], err, strings.TrimSpace(string(out)))
	}
	return nil
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}
