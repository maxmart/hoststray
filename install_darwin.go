package main

import (
	"fmt"
	"os"
)

func noteInstalledVersion() {}

// runUninstall is for the Windows uninstaller; on macOS the app is removed by
// moving it to the Trash.
func runUninstall() int {
	fmt.Fprintln(os.Stderr, "--uninstall is only used on Windows")
	return 2
}
