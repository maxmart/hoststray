package platform

/*
#cgo CFLAGS: -Wno-deprecated-declarations
#cgo LDFLAGS: -framework Security
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <Security/Authorization.h>
#include <Security/AuthorizationTags.h>

// authorize shows the system's admin authentication dialog with our prompt
// and icon. It asks for the password; macOS offers no Touch ID for this right.
static OSStatus authorize(AuthorizationRef *ref, const char *prompt, const char *icon) {
	OSStatus st = AuthorizationCreate(NULL, kAuthorizationEmptyEnvironment, kAuthorizationFlagDefaults, ref);
	if (st != errAuthorizationSuccess) return st;
	AuthorizationItem right = {kAuthorizationRightExecute, 0, NULL, 0};
	AuthorizationRights rights = {1, &right};
	AuthorizationItem env[2] = {
		{kAuthorizationEnvironmentPrompt, strlen(prompt), (void *)prompt, 0},
		{kAuthorizationEnvironmentIcon, strlen(icon), (void *)icon, 0},
	};
	AuthorizationEnvironment environment = {icon[0] ? 2 : 1, env};
	AuthorizationFlags flags = kAuthorizationFlagInteractionAllowed | kAuthorizationFlagPreAuthorize | kAuthorizationFlagExtendRights;
	return AuthorizationCopyRights(*ref, &rights, &environment, flags, NULL);
}

// execute runs tool as root and returns a pipe to its standard output.
static OSStatus execute(AuthorizationRef ref, const char *tool, char **argv, int *fd) {
	FILE *pipe = NULL;
	OSStatus st = AuthorizationExecuteWithPrivileges(ref, tool, kAuthorizationFlagDefaults, argv, &pipe);
	if (st == errAuthorizationSuccess && pipe != NULL) {
		*fd = dup(fileno(pipe));
		fclose(pipe);
	}
	return st;
}
*/
import "C"

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

// runAsAdmin runs tool with args as root after the system's admin dialog,
// which names Hosts Tray and shows prompt. Nothing goes through a shell
// unless tool is one. Cancelling returns ErrCancelled.
//
// AuthorizationExecuteWithPrivileges is deprecated but still the only way to
// run a command as root after a native prompt without installing anything
// first. Only system tools and the helper's installer are run this way.
func runAsAdmin(prompt, tool string, args ...string) error {
	cPrompt, cIcon := C.CString(prompt), C.CString(appIcon())
	defer C.free(unsafe.Pointer(cPrompt))
	defer C.free(unsafe.Pointer(cIcon))
	var ref C.AuthorizationRef
	st := C.authorize(&ref, cPrompt, cIcon)
	if ref != nil {
		defer C.AuthorizationFree(ref, C.kAuthorizationFlagDestroyRights)
	}
	switch st {
	case C.errAuthorizationSuccess:
	case C.errAuthorizationCanceled:
		return ErrCancelled
	default:
		return fmt.Errorf("authorization failed (%d)", int(st))
	}

	// Run it through sh to learn its exit status and to reap the process
	// AuthorizationExecuteWithPrivileges starts (it can't tell us either).
	wrapper := `echo "pid $$ $PPID"; exec 2>&1; "$0" "$@"; echo "exit $?"`
	argv := append([]string{"-c", wrapper, tool}, args...)
	cArgs := make([]*C.char, len(argv)+1)
	for i, a := range argv {
		cArgs[i] = C.CString(a)
		defer C.free(unsafe.Pointer(cArgs[i]))
	}
	cSh := C.CString("/bin/sh")
	defer C.free(unsafe.Pointer(cSh))
	var fd C.int = -1
	if st := C.execute(ref, cSh, &cArgs[0], &fd); st != C.errAuthorizationSuccess {
		return fmt.Errorf("running %s as root failed (%d)", tool, int(st))
	}
	if fd < 0 {
		return errors.New("running " + tool + " as root: no output pipe")
	}
	out := os.NewFile(uintptr(fd), "authorized")
	defer out.Close()

	code := -1
	var pids []int
	var msg []string
	sc := bufio.NewScanner(out)
	for sc.Scan() {
		line := sc.Text()
		if f := strings.Fields(line); len(f) == 3 && f[0] == "pid" && pids == nil {
			for _, s := range f[1:] {
				if n, err := strconv.Atoi(s); err == nil {
					pids = append(pids, n)
				}
			}
		} else if n, err := strconv.Atoi(strings.TrimPrefix(line, "exit ")); err == nil && strings.HasPrefix(line, "exit ") {
			code = n
		} else {
			msg = append(msg, line)
		}
	}
	for _, pid := range pids { // whichever of them is our child
		var ws syscall.WaitStatus
		syscall.Wait4(pid, &ws, 0, nil)
	}
	if code != 0 {
		return fmt.Errorf("%s failed (exit %d): %s", tool, code, strings.TrimSpace(strings.Join(msg, "\n")))
	}
	return nil
}

// RunAsAdmin is runAsAdmin for other packages (the updater).
func RunAsAdmin(prompt, tool string, args ...string) error { return runAsAdmin(prompt, tool, args...) }
