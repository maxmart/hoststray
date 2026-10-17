package platform

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func systemHostsPath() string {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	return filepath.Join(root, "System32", "drivers", "etc", "hosts")
}

// hidden runs a console program without flashing a console window.
func hidden(name string, args ...string) *exec.Cmd {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
	return cmd
}

func psQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

// runElevated runs a cmd.exe command line through a UAC prompt and waits for
// it. Declining the prompt returns ErrCancelled.
func runElevated(cmdline string) error {
	script := fmt.Sprintf(`try { $p = Start-Process -FilePath cmd.exe -ArgumentList %s -Verb RunAs -Wait -PassThru -WindowStyle Hidden } catch { exit 1223 }; exit $p.ExitCode`,
		psQuote("/c "+cmdline))
	err := hidden("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script).Run()
	if ee, ok := err.(*exec.ExitError); ok && ee.ExitCode() == 1223 {
		return ErrCancelled
	}
	return err
}

func cmdQuote(s string) string { return `"` + s + `"` }

func elevatedCopy(src, dst string) error {
	return runElevated("copy /Y " + cmdQuote(src) + " " + cmdQuote(dst) + " >nul && ipconfig /flushdns >nul")
}

func setUserWritable(path string, enable bool) error {
	name, err := currentUser()
	if err != nil {
		return err
	}
	if enable {
		return runElevated("icacls " + cmdQuote(path) + " /grant " + cmdQuote(name+":(M)") + " >nul")
	}
	return runElevated("icacls " + cmdQuote(path) + " /remove:g " + cmdQuote(name) + " >nul")
}

func trustCA(certPath string) error {
	// The current user's Root store needs no admin; Windows shows its own
	// security warning asking the user to confirm.
	out, err := hidden("certutil.exe", "-user", "-addstore", "Root", certPath).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func trustCommand(certPath string) string {
	return `certutil -user -addstore Root "` + certPath + `"`
}

var (
	user32         = windows.NewLazySystemDLL("user32.dll")
	procMessageBox = user32.NewProc("MessageBoxW")
)

const (
	mbOK          = 0x0
	mbYesNoCancel = 0x3
	mbIconInfo    = 0x40
	mbTopmost     = 0x40000
	mbSetFg       = 0x10000
	idYes         = 6
	idNo          = 7
)

// ask maps the first two buttons onto Yes/No (MessageBox can't relabel its
// buttons, so they're named in the text); Cancel or closing returns -1.
func ask(title, message string, buttons []string) int {
	style := uintptr(mbOK)
	if len(buttons) >= 2 {
		style = mbYesNoCancel
		message += fmt.Sprintf("\n\nYes: %s\nNo: %s", buttons[0], buttons[1])
	}
	t, _ := windows.UTF16PtrFromString(title)
	m, _ := windows.UTF16PtrFromString(message)
	r, _, _ := procMessageBox.Call(0, uintptr(unsafe.Pointer(m)), uintptr(unsafe.Pointer(t)), style|mbIconInfo|mbTopmost|mbSetFg)
	switch {
	case len(buttons) <= 1:
		return 0
	case r == idYes:
		return 0
	case r == idNo:
		return 1
	default:
		return -1
	}
}

func openURL(url string) error {
	verb, _ := windows.UTF16PtrFromString("open")
	u, _ := windows.UTF16PtrFromString(url)
	return windows.ShellExecute(0, verb, u, nil, nil, windows.SW_SHOWNORMAL)
}

func copyToClipboard(text string) error {
	cmd := hidden("cmd.exe", "/c", "clip")
	cmd.Stdin = strings.NewReader(text)
	return cmd.Run()
}

const runKey = `Software\Microsoft\Windows\CurrentVersion\Run`
const runValue = "Hosts Tray"

func loginItemEnabled() bool {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	v, _, err := k.GetStringValue(runValue)
	return err == nil && strings.EqualFold(strings.Trim(v, `"`), executable())
}

func setLoginItem(enable bool) error {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	if !enable {
		if err := k.DeleteValue(runValue); err != nil && err != registry.ErrNotExist {
			return err
		}
		return nil
	}
	return k.SetStringValue(runValue, `"`+executable()+`"`)
}
