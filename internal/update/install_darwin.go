package update

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"github.com/maxmart/hoststray/internal/platform"
)

// bundlePath is the running .app, from .../X.app/Contents/MacOS/binary.
func bundlePath() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	exe, _ = filepath.EvalSymlinks(exe)
	b := filepath.Dir(filepath.Dir(filepath.Dir(exe)))
	if !strings.HasSuffix(b, ".app") {
		return "", errors.New("not running from an app bundle; download the update manually")
	}
	return b, nil
}

var teamRe = regexp.MustCompile(`(?m)^TeamIdentifier=(.+)$`)

func team(app string) (string, error) {
	out, err := exec.Command("codesign", "-dv", app).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("codesign: %s", strings.TrimSpace(string(out)))
	}
	if m := teamRe.FindStringSubmatch(string(out)); m != nil {
		return strings.TrimSpace(m[1]), nil
	}
	return "", nil
}

// verifyApp checks the new bundle's signature, and that it's signed by the
// same team as the running app.
func verifyApp(newApp, current string) error {
	if out, err := exec.Command("codesign", "--verify", "--deep", "--strict", newApp).CombinedOutput(); err != nil {
		return fmt.Errorf("update signature invalid: %s", strings.TrimSpace(string(out)))
	}
	want, err := team(current)
	if err != nil {
		return err
	}
	got, err := team(newApp)
	if err != nil {
		return err
	}
	if got != want {
		return fmt.Errorf("update is signed by team %q, expected %q", got, want)
	}
	return nil
}

func install(zipPath string) error {
	bundle, err := bundlePath()
	if err != nil {
		return err
	}
	work, err := os.MkdirTemp(filepath.Dir(zipPath), "install-")
	if err != nil {
		return err
	}
	if out, err := exec.Command("ditto", "-x", "-k", zipPath, work).CombinedOutput(); err != nil {
		return fmt.Errorf("unzip: %s", out)
	}
	apps, _ := filepath.Glob(filepath.Join(work, "*.app"))
	if len(apps) != 1 {
		return errors.New("update archive doesn't contain one app")
	}
	newApp := apps[0]
	if err := verifyApp(newApp, bundle); err != nil {
		return err
	}
	old := filepath.Join(work, "previous.app")

	// Swap bundles; an app installed by the .pkg is root-owned, so fall back
	// to an admin prompt.
	if err := os.Rename(bundle, old); err == nil {
		if err := os.Rename(newApp, bundle); err != nil {
			os.Rename(old, bundle)
			return err
		}
	} else if errors.Is(err, os.ErrPermission) {
		if err := swapAsAdmin(bundle, newApp, old); err != nil {
			return err
		}
	} else {
		return err
	}
	return relaunch(bundle)
}

func swapAsAdmin(bundle, newApp, old string) error {
	err := platform.RunAsAdmin("Hosts Tray wants to install an update.", "/bin/sh", "-c",
		`/bin/mv "$0" "$2" && /bin/mv "$1" "$0"`, bundle, newApp, old)
	if errors.Is(err, platform.ErrCancelled) {
		return errors.New("update cancelled")
	}
	if err != nil {
		return fmt.Errorf("install update: %w", err)
	}
	return nil
}

// relaunch starts the new bundle once this process has exited, keeping the
// app's configuration environment (open doesn't pass it on by itself).
func relaunch(bundle string) error {
	args := []string{"-c", `pid="$1"; shift; while kill -0 "$pid" 2>/dev/null; do sleep 0.2; done; exec open "$@"`, "sh", fmt.Sprint(os.Getpid())}
	for _, kv := range os.Environ() {
		for _, prefix := range []string{"HOSTSTRAY_", "HOSTS_PATH=", "PORT=", "LISTEN_HOST=", "FORWARD_HOST=", "PROXY_TIMEOUT="} {
			if strings.HasPrefix(kv, prefix) {
				args = append(args, "--env", kv)
			}
		}
	}
	args = append(args, bundle)
	cmd := exec.Command("/bin/sh", args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	return cmd.Start()
}

func cleanup() {}
