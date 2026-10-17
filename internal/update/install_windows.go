package update

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

// install swaps the executable: a running executable can be renamed (even on
// Windows), so move it aside, put the new one in its place and start it.
func install(downloaded string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	exe, _ = filepath.EvalSymlinks(exe)
	old := exe + ".old"
	os.Remove(old)
	if err := os.Rename(exe, old); err != nil {
		return err
	}
	if err := copyFile(downloaded, exe); err != nil {
		os.Rename(old, exe)
		return err
	}
	cmd := exec.Command(exe, os.Args[1:]...)
	cmd.Env = append(os.Environ(), "HOSTSTRAY_RESTART=1") // wait for our port to free up
	detach(cmd)
	if err := cmd.Start(); err != nil {
		os.Remove(exe)
		os.Rename(old, exe)
		return err
	}
	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// cleanup removes the previous executable left by an update.
func cleanup() {
	if exe, err := os.Executable(); err == nil {
		os.Remove(exe + ".old")
	}
}

func detach(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x00000008 | 0x00000200} // DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
}
