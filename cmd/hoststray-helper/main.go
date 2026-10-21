//go:build darwin

// Command hoststray-helper is the root daemon behind "Change hosts without
// password" (see internal/helper). The app ships it next to its own binary
// and runs it as root, through the admin password prompt, to install or
// remove it:
//
//	hoststray-helper --install <uid> <app binary>
//	hoststray-helper --uninstall <uid>
//
// launchd then runs the installed copy with --run.
package main

import (
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/maxmart/hoststray/internal/helper"
)

func main() {
	arg := func(i int) string {
		if len(os.Args) <= i {
			return ""
		}
		return os.Args[i]
	}
	var err error
	switch arg(1) {
	case "--run":
		var uid uint64
		if uid, err = strconv.ParseUint(arg(2), 10, 32); err == nil {
			err = helper.Run(uint32(uid), arg(3))
		}
	case "--install":
		err = helper.Install(arg(2), arg(3))
	case "--uninstall":
		var uid uint32
		if uid, _, err = helper.LookupUID(arg(2)); err == nil {
			err = helper.Uninstall(uid)
		}
	default:
		fmt.Fprintln(os.Stderr, "usage: hoststray-helper --install <uid> <app binary> | --uninstall <uid>")
		os.Exit(2)
	}
	if err != nil {
		log.Print(err)
		os.Exit(1)
	}
}
