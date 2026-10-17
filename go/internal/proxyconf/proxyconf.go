// Package proxyconf parses and serializes proxy.conf.
//
// One rule per line:   <pattern> -> <target>
//
//   - -> :80                     all HTTPS web traffic -> 127.0.0.1:80
//     wss://*/cmweb -> :5124       websocket upgrades under /cmweb -> :5124
//     https://*/api -> 1.2.3.4:81  (host may be specified on the target)
//
// Blank lines and #-comments are preserved verbatim, and a line keeps its
// original text unless it's edited. The JSON shape matches proxy-config.js.
package proxyconf

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

const DefaultHost = "127.0.0.1"

const DefaultConf = "# Proxy routes — one \"<pattern> -> <target>\" per line.\n" +
	"#   <pattern>:  *  = all traffic   |   wss://*/path = websocket upgrades under /path\n" +
	"#   <target>:   :PORT = 127.0.0.1:PORT   |   host:PORT = a specific host\n" +
	"# Edit these from the tray menu: \"Edit proxy routes…\"\n" +
	"\n" +
	"* -> :80\n"

type Node struct {
	T           string  `json:"t"` // "raw" or "route"
	Raw         *string `json:"raw"`
	WS          bool    `json:"ws"`
	Proto       string  `json:"proto"`
	HostPattern string  `json:"hostPattern"`
	PathPrefix  string  `json:"pathPrefix"`
	TargetHost  string  `json:"targetHost"`
	TargetPort  int     `json:"targetPort"`
}

type Config struct {
	EOL   string  `json:"eol"`
	Nodes []*Node `json:"nodes"`
}

// MarshalJSON keeps raw nodes minimal, like the JS version.
func (n *Node) MarshalJSON() ([]byte, error) {
	if n.T != "route" {
		return json.Marshal(struct {
			T   string  `json:"t"`
			Raw *string `json:"raw"`
		}{n.T, n.Raw})
	}
	type plain Node
	return json.Marshal((*plain)(n))
}

var protoRe = regexp.MustCompile(`^([a-zA-Z]+)://(.*)$`)

func parseTarget(s string) (host string, port int, ok bool) {
	s = strings.TrimSpace(s)
	host = DefaultHost
	portStr := s
	if strings.HasPrefix(s, ":") {
		portStr = s[1:]
	} else if i := strings.LastIndex(s, ":"); i >= 0 {
		if s[:i] != "" {
			host = s[:i]
		}
		portStr = s[i+1:]
	}
	port, ok = parseIntPrefix(portStr)
	return host, port, ok
}

// parseIntPrefix mimics JavaScript's parseInt(s, 10): leading whitespace and
// sign, then as many digits as possible.
func parseIntPrefix(s string) (int, bool) {
	s = strings.TrimLeft(s, " \t")
	end := 0
	if end < len(s) && (s[end] == '+' || s[end] == '-') {
		end++
	}
	start := end
	for end < len(s) && s[end] >= '0' && s[end] <= '9' {
		end++
	}
	if end == start {
		return 0, false
	}
	n, err := strconv.Atoi(s[:end])
	return n, err == nil
}

func parsePattern(s string) (proto string, ws bool, hostPattern, pathPrefix string) {
	s = strings.TrimSpace(s)
	rest := s
	if m := protoRe.FindStringSubmatch(s); m != nil {
		proto = strings.ToLower(m[1])
		rest = m[2]
	}
	ws = proto == "ws" || proto == "wss"
	hostPattern = rest
	if i := strings.Index(rest, "/"); i >= 0 {
		hostPattern = rest[:i]
		pathPrefix = rest[i:]
	}
	if hostPattern == "" {
		hostPattern = "*"
	}
	return
}

func Parse(text string) *Config {
	eol := "\n"
	if strings.Contains(text, "\r\n") {
		eol = "\r\n"
	}
	cfg := &Config{EOL: eol, Nodes: []*Node{}}
	for _, raw := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		raw := raw
		trimmed := strings.TrimSpace(raw)
		arrow := strings.Index(raw, "->")
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || arrow < 0 {
			cfg.Nodes = append(cfg.Nodes, &Node{T: "raw", Raw: &raw})
			continue
		}
		proto, ws, hostPattern, pathPrefix := parsePattern(raw[:arrow])
		host, port, ok := parseTarget(raw[arrow+2:])
		if !ok {
			cfg.Nodes = append(cfg.Nodes, &Node{T: "raw", Raw: &raw}) // unparseable target
			continue
		}
		cfg.Nodes = append(cfg.Nodes, &Node{T: "route", Raw: &raw, WS: ws, Proto: proto,
			HostPattern: hostPattern, PathPrefix: pathPrefix, TargetHost: host, TargetPort: port})
	}
	return cfg
}

func lineFor(n *Node) string {
	if n.Raw != nil {
		return *n.Raw // raw nodes, and untouched routes, verbatim
	}
	if n.T != "route" {
		return ""
	}
	proto := n.Proto
	if n.WS && proto == "" {
		proto = "wss"
	}
	hostPattern := n.HostPattern
	if hostPattern == "" {
		hostPattern = "*"
	}
	pattern := hostPattern + n.PathPrefix
	if proto != "" {
		pattern = proto + "://" + pattern
	}
	host := ""
	if n.TargetHost != "" && n.TargetHost != DefaultHost {
		host = n.TargetHost
	}
	return pattern + " -> " + host + ":" + strconv.Itoa(n.TargetPort)
}

func Serialize(cfg *Config) string {
	lines := make([]string, len(cfg.Nodes))
	for i, n := range cfg.Nodes {
		lines[i] = lineFor(n)
	}
	eol := cfg.EOL
	if eol == "" {
		eol = "\n"
	}
	return strings.Join(lines, eol)
}

// Route is a resolved routing rule for the proxy.
type Route struct {
	WS         bool   `json:"ws"`
	PathPrefix string `json:"pathPrefix"`
	Host       string `json:"host"`
	Port       int    `json:"port"`
}

// Routes resolves the config into web and websocket route lists. A non-empty
// forwardHost replaces the default host, but never an explicit one.
func Routes(cfg *Config, forwardHost string) (web, ws []Route) {
	web, ws = []Route{}, []Route{}
	for _, n := range cfg.Nodes {
		if n.T != "route" {
			continue
		}
		r := Route{WS: n.WS, PathPrefix: n.PathPrefix, Host: n.TargetHost, Port: n.TargetPort}
		if forwardHost != "" && n.TargetHost == DefaultHost {
			r.Host = forwardHost
		}
		if r.WS {
			ws = append(ws, r)
		} else {
			web = append(web, r)
		}
	}
	return web, ws
}

// EnsureFile creates dir/proxy.conf with the default routes if it's missing
// and returns its path.
func EnsureFile(dir string) (string, error) {
	path := filepath.Join(dir, "proxy.conf")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return "", err
		}
		if err := os.WriteFile(path, []byte(DefaultConf), 0o644); err != nil {
			return "", err
		}
	}
	return path, nil
}
