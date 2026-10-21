package helper

import (
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// macOS has no way to reset another program's TCP connection, so pf does it:
// for a while, packets to the dropped addresses on port 80 and 443 are
// answered with a reset unless they belong to a connection pf saw start. A
// browser's next request on an old keep-alive connection fails, and it
// retries on a new one, after looking the hostname up again. New connections
// are not affected.
//
// The rules go into anchors under com.apple/*, which the stock /etc/pf.conf
// evaluates, and pf is enabled with a reference (pfctl -E) that is released
// afterwards, so nothing else's use of pf is disturbed.

const (
	Pfctl = "/sbin/pfctl"
	// BlockFor covers how long browsers keep an idle connection for reuse
	// (Chrome: 5 minutes).
	BlockFor = 6 * time.Minute
)


// StaleRules are the pf rules that reset old connections to addrs.
func StaleRules(addrs []netip.Addr) string {
	var list []string
	for _, a := range addrs {
		list = append(list, a.String())
	}
	to := "{ " + strings.Join(list, ", ") + " } port { 80, 443 }"
	return "pass out quick proto tcp from any to " + to + " flags S/SA keep state\n" +
		"block return out quick proto tcp from any to " + to + "\n"
}

// anyFor is the "from anywhere" network for pfctl -k with a's family.
func anyFor(a netip.Addr) string {
	if a.Is6() {
		return "::/0"
	}
	return "0.0.0.0/0"
}

// PromptScript is a shell snippet for the password prompt's root shell that
// resets stale connections to addrs like the daemon does, using only system
// tools, and lifts the block after BlockFor from a background job.
func PromptScript(addrs []netip.Addr) string {
	addrs = Droppable(addrs)
	if len(addrs) == 0 {
		return ""
	}
	var kill []string
	for _, a := range addrs {
		kill = append(kill, Pfctl+" -k "+anyFor(a)+" -k "+a.String())
	}
	return `a=com.apple/hoststray-$$
printf '%s' '` + StaleRules(addrs) + `' | ` + Pfctl + ` -a $a -f - 2>/dev/null || exit 0
t=$(` + Pfctl + ` -E 2>&1 | sed -n 's/^Token : //p')
` + strings.Join(kill, " 2>/dev/null\n") + ` 2>/dev/null
(sleep ` + strconv.Itoa(int(BlockFor.Seconds())) + `; ` + Pfctl + ` -a $a -F rules; [ -z "$t" ] || ` + Pfctl + ` -X $t) </dev/null >/dev/null 2>&1 &
`
}
