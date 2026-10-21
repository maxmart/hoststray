// Command hoststray-helper is the service behind "Switch groups without
// password" on Windows (see internal/helper). The app carries it inside its
// own exe and installs it, from a UAC prompt, to Program Files; the service
// manager then runs it as
//
//	hoststray-helper.exe --service <user SID> <app exe>
package main

import (
	"fmt"
	"log"
	"os"

	"github.com/maxmart/hoststray/internal/helper"
)

func main() {
	if len(os.Args) != 4 || os.Args[1] != "--service" {
		fmt.Fprintln(os.Stderr, "usage: hoststray-helper --service <user SID> <app exe>")
		os.Exit(2)
	}
	if err := helper.RunService(os.Args[2], os.Args[3]); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}
