package app

import (
	"errors"
	"strings"
	"time"

	"github.com/maxmart/hoststray/internal/hosts"
	"github.com/maxmart/hoststray/internal/proxyconf"
)

// An export carries what's worth moving to another computer: the hosts groups
// and the proxy routes, as plain text in their own file formats. The rest of
// the hosts file is machine-specific, and the CA stays on its machine.
//
//	# Hosts Tray export ...
//	[hosts]
//	#==== DEV
//	127.0.0.1  app.example.com
//	#====
//	[routes]
//	* -> :3000

const (
	hostsSection  = "[hosts]"
	routesSection = "[routes]"
)

var ErrNotExport = errors.New("this isn't a Hosts Tray export (no [hosts] or [routes] section)")

// Export returns the groups and routes as an export.
func (a *App) Export() (string, error) {
	doc, err := a.LoadHosts()
	if err != nil {
		return "", err
	}
	cfg, err := a.LoadProxyConf()
	if err != nil {
		return "", err
	}
	groups := &hosts.Doc{EOL: "\n"}
	for _, n := range doc.Nodes {
		if n.T == "group" {
			groups.Nodes = append(groups.Nodes, n)
		}
	}
	var b strings.Builder
	b.WriteString("# Hosts Tray export, " + time.Now().Format("2006-01-02") + " (version " + a.cfg.Version + ")\n")
	b.WriteString("# Import it in the Hosts Tray console: Settings > Import.\n\n")
	b.WriteString(hostsSection + "\n")
	if len(groups.Nodes) > 0 {
		b.WriteString(hosts.Serialize(groups) + "\n")
	}
	b.WriteString("\n" + routesSection + "\n")
	for _, line := range routeLines(cfg) {
		b.WriteString(line + "\n")
	}
	return b.String(), nil
}

func routeLines(cfg *proxyconf.Config) []string {
	lines := []string{}
	for _, n := range cfg.Nodes {
		if n.T == "route" {
			lines = append(lines, strings.TrimSpace(proxyconf.Serialize(&proxyconf.Config{Nodes: []*proxyconf.Node{n}})))
		}
	}
	return lines
}

type parsedExport struct {
	groups    []*hosts.Node
	routes    *proxyconf.Config // nil without a [routes] section
	hasHosts  bool
	ungrouped int // entries outside any group, which aren't imported
}

func parseExport(text string) (*parsedExport, error) {
	var section string
	parts := map[string][]string{}
	for _, line := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		if t := strings.TrimSpace(line); t == hostsSection || t == routesSection {
			section = t
			parts[section] = []string{}
			continue
		}
		if section != "" {
			parts[section] = append(parts[section], line)
		}
	}
	if section == "" {
		return nil, ErrNotExport
	}
	p := &parsedExport{}
	if lines, ok := parts[hostsSection]; ok {
		p.hasHosts = true
		for _, n := range hosts.Parse(strings.Join(lines, "\n")).Nodes {
			switch n.T {
			case "group":
				p.groups = append(p.groups, n)
			case "entry":
				p.ungrouped++
			}
		}
	}
	if lines, ok := parts[routesSection]; ok {
		p.routes = &proxyconf.Config{Nodes: []*proxyconf.Node{}}
		for _, n := range proxyconf.Parse(strings.Join(lines, "\n")).Nodes {
			if n.T == "route" {
				p.routes.Nodes = append(p.routes.Nodes, n)
			}
		}
	}
	return p, nil
}

// ImportPlan says what an import would change.
type ImportPlan struct {
	Groups    []GroupChange `json:"groups"`
	Routes    *RoutesChange `json:"routes,omitempty"` // nil when the export has no routes
	Ungrouped int           `json:"ungrouped"`        // entries outside groups, skipped
}

type GroupChange struct {
	Name    string `json:"name"`
	Action  string `json:"action"` // "add", "replace" or "same"
	Before  int    `json:"before"` // hostnames now
	After   int    `json:"after"`  // hostnames after the import
	Enabled bool   `json:"enabled"`
}

type RoutesChange struct {
	Before  []string `json:"before"`
	After   []string `json:"after"`
	Changed bool     `json:"changed"`
}

func countEntries(g *hosts.Node) int {
	n := 0
	for _, c := range g.Children {
		if c.T == "entry" {
			n++
		}
	}
	return n
}

func groupText(g *hosts.Node) string {
	return hosts.Serialize(&hosts.Doc{EOL: "\n", Nodes: []*hosts.Node{g}})
}

func findGroup(doc *hosts.Doc, name string) int {
	for i, n := range doc.Nodes {
		if n.T == "group" && n.Name == name {
			return i
		}
	}
	return -1
}

// plan works out the import against the current files.
func (a *App) plan(p *parsedExport) (*ImportPlan, *hosts.Doc, *proxyconf.Config, error) {
	doc, err := a.LoadHosts()
	if err != nil {
		return nil, nil, nil, err
	}
	cfg, err := a.LoadProxyConf()
	if err != nil {
		return nil, nil, nil, err
	}
	plan := &ImportPlan{Groups: []GroupChange{}, Ungrouped: p.ungrouped}
	for _, g := range p.groups {
		ch := GroupChange{Name: g.Name, Action: "add", After: countEntries(g), Enabled: hosts.Groups(&hosts.Doc{Nodes: []*hosts.Node{g}})[0].Enabled}
		if i := findGroup(doc, g.Name); i >= 0 {
			ch.Before = countEntries(doc.Nodes[i])
			ch.Action = "replace"
			if groupText(doc.Nodes[i]) == groupText(g) {
				ch.Action = "same"
			}
		}
		plan.Groups = append(plan.Groups, ch)
	}
	if p.routes != nil {
		before, after := routeLines(cfg), routeLines(p.routes)
		plan.Routes = &RoutesChange{Before: before, After: after, Changed: strings.Join(before, "\n") != strings.Join(after, "\n")}
	}
	return plan, doc, cfg, nil
}

// PreviewImport reports what ImportExport would change, without changing it.
func (a *App) PreviewImport(text string) (*ImportPlan, error) {
	p, err := parseExport(text)
	if err != nil {
		return nil, err
	}
	plan, _, _, err := a.plan(p)
	return plan, err
}

// ImportExport applies an export: groups are merged by name (same name
// replaces, new names are added, others are left alone) and the routes, if
// the export has them, replace the current ones. The hosts file is written
// first; if that is cancelled or fails, the routes are left as they were.
func (a *App) ImportExport(text string) (*ImportPlan, SaveResult, error) {
	p, err := parseExport(text)
	if err != nil {
		return nil, SaveResult{}, err
	}
	plan, doc, cfg, err := a.plan(p)
	if err != nil {
		return nil, SaveResult{}, err
	}

	res := SaveResult{OK: true}
	changedHosts := false
	for i, g := range p.groups {
		switch plan.Groups[i].Action {
		case "replace":
			doc.Nodes[findGroup(doc, g.Name)] = g
			changedHosts = true
		case "add":
			// Before the trailing blank line(s), so the file keeps its final newline.
			at := len(doc.Nodes)
			for at > 0 && doc.Nodes[at-1].T == "raw" && doc.Nodes[at-1].Raw != nil && strings.TrimSpace(*doc.Nodes[at-1].Raw) == "" {
				at--
			}
			doc.Nodes = append(doc.Nodes[:at], append([]*hosts.Node{g}, doc.Nodes[at:]...)...)
			changedHosts = true
		}
	}
	if changedHosts {
		if res = a.SaveHosts(doc); !res.OK {
			return plan, res, res.err
		}
	}

	if plan.Routes != nil && plan.Routes.Changed {
		// Keep this file's leading comments, then the imported routes.
		next := &proxyconf.Config{EOL: cfg.EOL, Nodes: []*proxyconf.Node{}}
		for _, n := range cfg.Nodes {
			if n.T == "route" {
				break
			}
			next.Nodes = append(next.Nodes, n)
		}
		for len(next.Nodes) > 0 && strings.TrimSpace(*next.Nodes[len(next.Nodes)-1].Raw) == "" {
			next.Nodes = next.Nodes[:len(next.Nodes)-1] // no routes: drop trailing blanks
		}
		if len(next.Nodes) > 0 {
			next.Nodes = append(next.Nodes, &proxyconf.Node{T: "raw", Raw: new(string)})
		}
		next.Nodes = append(next.Nodes, p.routes.Nodes...)
		if last := len(cfg.Nodes) - 1; last < 0 || (cfg.Nodes[last].T == "raw" && *cfg.Nodes[last].Raw == "") {
			next.Nodes = append(next.Nodes, &proxyconf.Node{T: "raw", Raw: new(string)}) // keep the final newline
		}
		if r := a.SaveProxyConf(next); !r.OK {
			return plan, r, r.err
		}
	}
	return plan, res, nil
}
