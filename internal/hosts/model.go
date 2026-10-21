// Package hosts parses and serializes the hosts file.
//
// Design goal: faithful round-trip. Parsing then serializing an unedited
// document reproduces the original file byte-for-byte (modulo a single
// normalized line ending). Anything not explicitly modelled -- headers, blank
// lines, stray comments, inline "# notes", odd whitespace, non-local IPs -- is
// carried through verbatim via each node's Raw.
//
// A node is only regenerated from its structured fields when Raw is nil, which
// the editor does when it actually changes that node.
//
// The JSON shape matches the original hosts-model.js so the web editor can
// round-trip documents through the API unchanged.
package hosts

import (
	"encoding/json"
	"regexp"
	"strings"
)

const GroupPrefix = "#===="

var (
	ipv4      = regexp.MustCompile(`^\d{1,3}(?:\.\d{1,3}){3}$`)
	entryLine = regexp.MustCompile(`^(\S+)\s+(\S+)\s*(.*)$`)
)

// Node is one line ("raw" or "entry") or a "group" of lines.
type Node struct {
	T string // "raw", "entry" or "group"

	// raw and entry
	Raw     *string
	Enabled bool
	IP      string
	Host    string
	Comment string

	// group
	Name     string
	RawOpen  *string
	RawClose *string
	Children []*Node
}

type Doc struct {
	EOL   string  `json:"eol"`
	Nodes []*Node `json:"nodes"`
}

type Group struct {
	Name    string  `json:"name"`
	Enabled bool    `json:"enabled"`
	Entries []Entry `json:"entries"`
}

type Entry struct {
	IP      string `json:"ip"`
	Host    string `json:"host"`
	Enabled bool   `json:"enabled"`
}

func (n *Node) MarshalJSON() ([]byte, error) {
	switch n.T {
	case "group":
		children := n.Children
		if children == nil {
			children = []*Node{}
		}
		return json.Marshal(struct {
			T        string  `json:"t"`
			Name     string  `json:"name"`
			RawOpen  *string `json:"rawOpen"`
			RawClose *string `json:"rawClose"`
			Children []*Node `json:"children"`
		}{n.T, n.Name, n.RawOpen, n.RawClose, children})
	case "entry":
		return json.Marshal(struct {
			T       string  `json:"t"`
			Raw     *string `json:"raw"`
			Enabled bool    `json:"enabled"`
			IP      string  `json:"ip"`
			Host    string  `json:"host"`
			Comment string  `json:"comment"`
		}{n.T, n.Raw, n.Enabled, n.IP, n.Host, n.Comment})
	default:
		return json.Marshal(struct {
			T   string  `json:"t"`
			Raw *string `json:"raw"`
		}{n.T, n.Raw})
	}
}

func (n *Node) UnmarshalJSON(b []byte) error {
	var v struct {
		T        string  `json:"t"`
		Raw      *string `json:"raw"`
		Enabled  bool    `json:"enabled"`
		IP       string  `json:"ip"`
		Host     string  `json:"host"`
		Comment  string  `json:"comment"`
		Name     string  `json:"name"`
		RawOpen  *string `json:"rawOpen"`
		RawClose *string `json:"rawClose"`
		Children []*Node `json:"children"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	*n = Node{T: v.T, Raw: v.Raw, Enabled: v.Enabled, IP: v.IP, Host: v.Host, Comment: v.Comment,
		Name: v.Name, RawOpen: v.RawOpen, RawClose: v.RawClose, Children: v.Children}
	return nil
}

func isMarker(line string) bool { return strings.HasPrefix(line, GroupPrefix) }

func markerName(line string) string { return strings.TrimSpace(line[len(GroupPrefix):]) }

// trimJS trims whitespace the way JavaScript's String.prototype.trim does
// (close enough for hosts files: ASCII whitespace plus NBSP/BOM).
func trimJS(s string) string { return strings.TrimSpace(strings.Trim(s, "\uFEFF\u00A0")) }

// ParseEntry interprets a single line as a host entry, optionally commented
// out. ok is false if the line isn't an IPv4 entry.
func ParseEntry(line string) (e Entry, comment string, ok bool) {
	enabled := true
	body := strings.TrimLeft(line, " \t\v\f\r\n\u00A0\uFEFF")
	if strings.HasPrefix(body, "#") {
		enabled = false
		body = body[1:]
	}
	m := entryLine.FindStringSubmatch(trimJS(body))
	if m == nil || !ipv4.MatchString(m[1]) {
		return Entry{}, "", false
	}
	return Entry{IP: m[1], Host: m[2], Enabled: enabled}, trimJS(m[3]), true
}

func strp(s string) *string { return &s }

func Parse(text string) *Doc {
	eol := "\n"
	if strings.Contains(text, "\r\n") {
		eol = "\r\n"
	}
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")

	doc := &Doc{EOL: eol, Nodes: []*Node{}}
	var group *Node

	for _, raw := range lines {
		if isMarker(raw) {
			if name := markerName(raw); name != "" {
				// Opening marker. A still-open group is flushed; Serialize
				// will give it an explicit closing marker.
				if group != nil {
					doc.Nodes = append(doc.Nodes, group)
				}
				group = &Node{T: "group", Name: name, RawOpen: strp(raw), Children: []*Node{}}
			} else if group != nil {
				group.RawClose = strp(raw)
				doc.Nodes = append(doc.Nodes, group)
				group = nil
			} else {
				doc.Nodes = append(doc.Nodes, &Node{T: "raw", Raw: strp(raw)})
			}
			continue
		}

		var node *Node
		if e, comment, ok := ParseEntry(raw); ok {
			node = &Node{T: "entry", Raw: strp(raw), Enabled: e.Enabled, IP: e.IP, Host: e.Host, Comment: comment}
		} else {
			node = &Node{T: "raw", Raw: strp(raw)}
		}
		if group != nil {
			group.Children = append(group.Children, node)
		} else {
			doc.Nodes = append(doc.Nodes, node)
		}
	}
	if group != nil {
		doc.Nodes = append(doc.Nodes, group) // unclosed group at EOF
	}
	return doc
}

// lineFor returns the text for an entry/raw node; ok is false if the node
// should be dropped (an edited entry with an empty host).
func lineFor(n *Node) (string, bool) {
	if n.T == "raw" {
		if n.Raw == nil {
			return "", true
		}
		return *n.Raw, true
	}
	if n.Raw != nil {
		return *n.Raw, true // untouched -> verbatim
	}
	host := strings.TrimSpace(n.Host)
	if host == "" {
		return "", false
	}
	ip := n.IP
	if ip == "" {
		ip = "127.0.0.1"
	}
	line := ip + "  " + host
	if !n.Enabled {
		line = "#" + line
	}
	if n.Comment != "" {
		line += "  " + n.Comment
	}
	return line, true
}

func Serialize(doc *Doc) string {
	var out []string
	for _, n := range doc.Nodes {
		if n.T == "group" {
			if n.RawOpen != nil {
				out = append(out, *n.RawOpen)
			} else {
				out = append(out, GroupPrefix+" "+n.Name)
			}
			for _, c := range n.Children {
				if line, ok := lineFor(c); ok {
					out = append(out, line)
				}
			}
			if n.RawClose != nil {
				out = append(out, *n.RawClose)
			} else {
				out = append(out, GroupPrefix)
			}
		} else if line, ok := lineFor(n); ok {
			out = append(out, line)
		}
	}
	eol := doc.EOL
	if eol == "" {
		eol = "\n"
	}
	return strings.Join(out, eol)
}

// Groups lists the groups and whether each is fully enabled (every entry on).
func Groups(doc *Doc) []Group {
	groups := []Group{}
	for _, n := range doc.Nodes {
		if n.T != "group" {
			continue
		}
		g := Group{Name: n.Name, Entries: []Entry{}}
		all := true
		for _, c := range n.Children {
			if c.T == "entry" {
				g.Entries = append(g.Entries, Entry{IP: c.IP, Host: c.Host, Enabled: c.Enabled})
				all = all && c.Enabled
			}
		}
		g.Enabled = len(g.Entries) > 0 && all
		groups = append(groups, g)
	}
	return groups
}

// SetGroup enables or disables every entry in the named group. It reports
// whether the group exists.
func SetGroup(doc *Doc, name string, enable bool) bool {
	for _, n := range doc.Nodes {
		if n.T != "group" || n.Name != name {
			continue
		}
		for _, c := range n.Children {
			if c.T == "entry" && c.Enabled != enable {
				c.Enabled = enable
				c.Raw = nil // regenerate this line on serialize
			}
		}
		return true
	}
	return false
}

// Active maps each hostname with an enabled entry to its address. Like the
// OS, the first enabled entry for a hostname wins.
func Active(doc *Doc) map[string]string {
	m := map[string]string{}
	var walk func([]*Node)
	walk = func(nodes []*Node) {
		for _, n := range nodes {
			switch {
			case n.T == "group":
				walk(n.Children)
			case n.T == "entry" && n.Enabled:
				host := strings.ToLower(n.Host)
				if _, ok := m[host]; !ok {
					m[host] = n.IP
				}
			}
		}
	}
	walk(doc.Nodes)
	return m
}

// AddEntries puts entries into the named group, creating the group at the
// end of the file if there is none. A hostname already in the group gets the
// new address. New lines follow the group's state (on when every entry is
// on); in a new group they are on. It returns the entries that changed
// something, as they now are, and whether the group was created.
func AddEntries(doc *Doc, group string, entries []Entry) (changed []Entry, created bool) {
	var g *Node
	for _, n := range doc.Nodes {
		if n.T == "group" && n.Name == group {
			g = n
			break
		}
	}
	if g == nil {
		g = &Node{T: "group", Name: group}
		created = true
		gap := []*Node{{T: "raw", Raw: strp("")}, g}
		if last := len(doc.Nodes) - 1; last >= 0 && doc.Nodes[last].T == "raw" && doc.Nodes[last].Raw != nil && *doc.Nodes[last].Raw == "" {
			// Keep the file's final newline after the new group.
			doc.Nodes = append(doc.Nodes[:last], append(gap, doc.Nodes[last])...)
		} else {
			doc.Nodes = append(doc.Nodes, gap...)
		}
	}
	on := true
	for _, c := range g.Children {
		if c.T == "entry" {
			on = on && c.Enabled
		}
	}
	for _, e := range entries {
		var found *Node
		for _, c := range g.Children {
			if c.T == "entry" && strings.EqualFold(c.Host, e.Host) {
				found = c
				break
			}
		}
		switch {
		case found == nil:
			g.Children = append(g.Children, &Node{T: "entry", IP: e.IP, Host: e.Host, Enabled: on})
			changed = append(changed, Entry{IP: e.IP, Host: e.Host, Enabled: on})
		case found.IP != e.IP:
			found.IP, found.Raw = e.IP, nil // regenerate this line on serialize
			changed = append(changed, Entry{IP: e.IP, Host: found.Host, Enabled: found.Enabled})
		}
	}
	return changed, created
}
