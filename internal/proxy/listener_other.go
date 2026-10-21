//go:build !windows

package proxy

import (
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// listenerName names the program listening on addr, if it runs as this user
// (lsof can't see other users' sockets without root).
func listenerName(addr string) string {
	host, port, _ := net.SplitHostPort(addr)
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	out, err := exec.Command("lsof", "-nP", "-iTCP@"+host+":"+port, "-sTCP:LISTEN", "-Fpc").Output()
	if err != nil {
		return ""
	}
	pid := strconv.Itoa(os.Getpid())
	var cur string
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "p") {
			cur = line[1:]
		} else if strings.HasPrefix(line, "c") && cur != pid {
			return line[1:] + " (pid " + cur + ")"
		}
	}
	return ""
}
