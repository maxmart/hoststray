package platform

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/maxmart/hoststray/internal/helper"
)

func systemHostsPath() string { return "/etc/hosts" }

// osascript runs an AppleScript with arguments passed as argv, so nothing
// needs escaping. Error -128 (user cancelled) maps to ErrCancelled.
func osascript(script string, args ...string) (string, error) {
	cmd := exec.Command("osascript", append([]string{"-e", script}, args...)...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		if strings.Contains(stderr.String(), "-128") {
			return "", ErrCancelled
		}
		return "", fmt.Errorf("%v: %s", err, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(string(out)), nil
}

func elevatedCopy(src, dst string, drop []netip.Addr) error {
	// cp keeps the destination's owner and permissions. Flushing the DNS cache
	// makes the change visible right away. Resetting connections uses only
	// system tools, and if it fails the hosts file was still written.
	return runAsAdmin("Hosts Tray wants to update your hosts file.", "/bin/sh", "-c",
		`cp "$0" "$1" && (dscacheutil -flushcache; killall -HUP mDNSResponder; true) && eval "$2"`,
		src, dst, helper.PromptScript(drop))
}

// setUserWritable grants or revokes the user's write access to path.
func setUserWritable(path string, enable bool) error {
	name, err := currentUser()
	if err != nil {
		return err
	}
	op := "+a"
	if !enable {
		op = "-a"
	}
	prompt := "Hosts Tray wants to let you edit the hosts file without a password."
	if !enable {
		prompt = "Hosts Tray wants to ask for your password when editing the hosts file again."
	}
	return runAsAdmin(prompt, "/bin/chmod", op, "user:"+name+" allow write,append", path)
}

func loginKeychain() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Library", "Keychains", "login.keychain-db")
}

func trustCA(certPath string) error {
	// User-level trust in the login keychain. macOS asks for the password
	// itself; no root needed.
	out, err := exec.Command("security", "add-trusted-cert", "-r", "trustRoot", "-k", loginKeychain(), certPath).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func trustCommand(certPath string) string {
	return fmt.Sprintf(`security add-trusted-cert -r trustRoot -k ~/Library/Keychains/login.keychain-db "%s"`, certPath)
}

func ask(title, message string, buttons []string) int {
	if len(buttons) == 0 {
		buttons = []string{"OK"}
	}
	script := `on run argv
	set btns to items 4 thru -1 of argv
	activate
	with timeout of 86400 seconds
		if item 3 of argv is "" then
			display dialog (item 2 of argv) with title (item 1 of argv) buttons btns default button (item -1 of btns) with icon note
		else
			display dialog (item 2 of argv) with title (item 1 of argv) buttons btns default button (item -1 of btns) with icon (POSIX file (item 3 of argv))
		end if
	end timeout
	return button returned of result
end run`
	// display dialog lists buttons left to right with the default on the
	// right, so pass them reversed.
	rev := make([]string, len(buttons))
	for i, b := range buttons {
		rev[len(buttons)-1-i] = b
	}
	out, err := osascript(script, append([]string{title, message, appIcon()}, rev...)...)
	if err != nil {
		return -1
	}
	for i, b := range buttons {
		if b == out {
			return i
		}
	}
	return -1
}

// appIcon is the bundle's icon when running from Hosts Tray.app, so dialogs
// don't show osascript's generic icon.
func appIcon() string {
	p := filepath.Join(filepath.Dir(executable()), "..", "Resources", "icon.icns")
	if _, err := os.Stat(p); err == nil {
		return p
	}
	return ""
}

func openURL(url string) error { return exec.Command("open", url).Run() }

func copyToClipboard(text string) error {
	cmd := exec.Command("pbcopy")
	cmd.Stdin = strings.NewReader(text)
	return cmd.Run()
}

const launchAgentLabel = "maxmart.hoststray"

func launchAgentPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Library", "LaunchAgents", launchAgentLabel+".plist")
}

func loginItemEnabled() bool {
	b, err := os.ReadFile(launchAgentPath())
	return err == nil && bytes.Contains(b, []byte(xmlEscape(executable())))
}

func setLoginItem(enable bool) error {
	if !enable {
		err := os.Remove(launchAgentPath())
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	plist := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>` + launchAgentLabel + `</string>
	<key>ProgramArguments</key>
	<array>
		<string>` + xmlEscape(executable()) + `</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>ProcessType</key>
	<string>Interactive</string>
</dict>
</plist>
`
	if err := os.MkdirAll(filepath.Dir(launchAgentPath()), 0o755); err != nil {
		return err
	}
	return os.WriteFile(launchAgentPath(), []byte(plist), 0o644)
}

func xmlEscape(s string) string {
	var b bytes.Buffer
	for _, r := range s {
		switch r {
		case '&':
			b.WriteString("&amp;")
		case '<':
			b.WriteString("&lt;")
		case '>':
			b.WriteString("&gt;")
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
