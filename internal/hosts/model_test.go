package hosts

import (
	"bytes"
	"encoding/json"
	"flag"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

var fixtures = []string{
	"",
	"\n",
	"127.0.0.1 localhost\n255.255.255.255 broadcasthost\n::1 localhost\n",
	"#==== Staging\n127.0.0.1  app.example.com\n127.0.0.1  api.example.com\n#====\n\n#==== Customer demo\n#127.0.0.1  demo.example.com\n#====\n",
	"# Copyright (c) 1993-2009 Microsoft Corp.\r\n#\r\n#==== Win\r\n127.0.0.1 a.test # note here\r\n#  127.0.0.1    b.test\r\n#====\r\n",
	"#==== Unclosed\n127.0.0.1 a.test\n#==== Next\n10.0.0.1 b.test extra words\n",
	"#====\n#==== \n   127.0.0.1\tspaced.test   trailing   \n#notanentry\n# 999.1.1.1 x\n#==== X\n#====\n",
	"\xef\xbb\xbf127.0.0.1 bom.test\n\u00a0127.0.0.1 nbsp.test\n",
}

func TestRoundTrip(t *testing.T) {
	for _, f := range fixtures {
		if strings.Contains(f, "Unclosed") {
			continue // unclosed groups gain a closing marker (checked below)
		}
		if got := Serialize(Parse(f)); got != f && got != strings.ReplaceAll(f, "\r\n", "\n") {
			t.Errorf("round trip changed:\n%q\n%q", f, got)
		}
	}
	if b, err := os.ReadFile("/etc/hosts"); err == nil {
		if got := Serialize(Parse(string(b))); got != string(b) {
			t.Errorf("/etc/hosts round trip changed")
		}
	}
}

func TestUnclosedGroupsGetClosed(t *testing.T) {
	got := Serialize(Parse(fixtures[5]))
	want := "#==== Unclosed\n127.0.0.1 a.test\n#====\n#==== Next\n10.0.0.1 b.test extra words\n\n#===="
	if got != want {
		t.Fatalf("got %q", got)
	}
	if Serialize(Parse(got)) != got {
		t.Fatal("not stable after closing")
	}
}

func TestGroupsAndToggle(t *testing.T) {
	doc := Parse(fixtures[3])
	g := Groups(doc)
	if len(g) != 2 || !g[0].Enabled || g[1].Enabled || g[0].Name != "Staging" || len(g[0].Entries) != 2 {
		t.Fatalf("groups: %+v", g)
	}
	if !SetGroup(doc, "Customer demo", true) || SetGroup(doc, "missing", true) {
		t.Fatal("SetGroup result")
	}
	want := strings.Replace(fixtures[3], "#127.0.0.1  demo", "127.0.0.1  demo", 1)
	if got := Serialize(doc); got != want {
		t.Fatalf("toggle on:\n%s", got)
	}
	SetGroup(doc, "Staging", false)
	if got := Serialize(doc); !strings.Contains(got, "#127.0.0.1  app.example.com\n#127.0.0.1  api.example.com") {
		t.Fatalf("toggle off:\n%s", got)
	}
	// Untouched entries keep their exact formatting.
	doc = Parse("#==== G\n127.0.0.1\t\tkeep.test  # c\n#127.0.0.1 off.test\n#====")
	SetGroup(doc, "G", true)
	if got := Serialize(doc); got != "#==== G\n127.0.0.1\t\tkeep.test  # c\n127.0.0.1  off.test\n#====" {
		t.Fatalf("formatting: %q", got)
	}
}

func TestJSONRoundTrip(t *testing.T) {
	for _, f := range fixtures {
		b, err := json.Marshal(Parse(f))
		if err != nil {
			t.Fatal(err)
		}
		var doc Doc
		if err := json.Unmarshal(b, &doc); err != nil {
			t.Fatal(err)
		}
		if Serialize(&doc) != Serialize(Parse(f)) {
			t.Errorf("JSON round trip changed %q", f)
		}
	}
	// Empty groups must have [] children, not null (the editor iterates them).
	b, _ := json.Marshal(Parse("#==== Empty\n#===="))
	if !strings.Contains(string(b), `"children":[]`) {
		t.Errorf("empty group JSON: %s", b)
	}
}

// randomHostsText builds hosts-like text out of tricky fragments.
func randomHostsText(r *rand.Rand) string {
	frags := []string{"127.0.0.1", "10.0.0.1", "999.1.1", "::1", "fe80::1%lo0", "a.test", "b.example.com",
		"#", "# ", "#====", "#==== G", "#====  Name with spaces ", " ", "\t", "  ", "comment", "#note", "x"}
	var lines []string
	for i := r.Intn(25); i >= 0; i-- {
		var parts []string
		for j := r.Intn(5); j >= 0; j-- {
			parts = append(parts, frags[r.Intn(len(frags))])
		}
		sep := []string{"", " ", "\t", "  "}[r.Intn(4)]
		lines = append(lines, strings.Join(parts, sep))
	}
	eol := "\n"
	if r.Intn(4) == 0 {
		eol = "\r\n"
	}
	return strings.Join(lines, eol)
}

// TestMatchesJS checks parse and serialize against the original hosts-model.js.
func TestMatchesJS(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	texts := append([]string{}, fixtures...)
	for i := 0; i < 400; i++ {
		texts = append(texts, randomHostsText(r))
	}

	var ops []map[string]any
	for _, s := range texts {
		ops = append(ops, map[string]any{"kind": "parse", "text": s})
	}
	// Edited documents: regenerate some entries and groups from their fields.
	var edited []*Doc
	for _, s := range texts {
		doc := Parse(s)
		for _, n := range doc.Nodes {
			for _, c := range append([]*Node{n}, n.Children...) {
				if c.T == "entry" && r.Intn(2) == 0 {
					c.Raw, c.Enabled = nil, r.Intn(2) == 0
					if r.Intn(5) == 0 {
						c.Host = ""
					}
				}
				if c.T == "group" && r.Intn(3) == 0 {
					c.RawOpen, c.RawClose = nil, nil
				}
			}
		}
		edited = append(edited, doc)
		ops = append(ops, map[string]any{"kind": "serialize", "doc": doc})
	}

	res := golden(t, ops)
	for i, s := range texts {
		got, _ := json.Marshal(Parse(s))
		if normalize(t, got) != normalize(t, res[i]) {
			t.Errorf("parse mismatch for %q\n go: %s\n js: %s", s, got, res[i])
		}
	}
	for i, doc := range edited {
		var js string
		json.Unmarshal(res[len(texts)+i], &js)
		if got := Serialize(doc); got != js {
			t.Errorf("serialize mismatch\n go: %q\n js: %q", got, js)
		}
	}
}

// The expected results were produced by the original JavaScript
// implementation (hosts-model.js) when the Go port replaced it. Regenerate only with a
// copy of that file: go test -run MatchesJS -update-golden=<path to hosts-model.js>
var updateGolden = flag.String("update-golden", "", "regenerate testdata/js_golden.json with this JS module")

func golden(t *testing.T, ops []map[string]any) []json.RawMessage {
	t.Helper()
	path := filepath.Join("testdata", "js_golden.json")
	if *updateGolden != "" {
		res := runJS(t, *updateGolden, ops)
		b, _ := json.MarshalIndent(map[string]any{"ops": ops, "results": res}, "", " ")
		os.MkdirAll("testdata", 0o755)
		if err := os.WriteFile(path, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var g struct {
		Ops     []json.RawMessage `json:"ops"`
		Results []json.RawMessage `json:"results"`
	}
	if err := json.Unmarshal(b, &g); err != nil {
		t.Fatal(err)
	}
	if len(g.Ops) != len(ops) {
		t.Fatalf("golden has %d cases, test generated %d", len(g.Ops), len(ops))
	}
	for i, op := range ops {
		got, _ := json.Marshal(op)
		if normalize(t, got) != normalize(t, g.Ops[i]) {
			t.Fatalf("test inputs changed (case %d); regenerate the golden file", i)
		}
	}
	return g.Results
}

func normalize(t *testing.T, b []byte) string {
	t.Helper()
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatalf("normalize: %v (%s)", err, b)
	}
	out, _ := json.Marshal(v)
	return string(out)
}

const jsRunner = `
const input = JSON.parse(require("fs").readFileSync(0, "utf8"));
const mod = require(input.module);
process.stdout.write(JSON.stringify(input.ops.map(op =>
  op.kind === "parse" ? mod.parse(op.text) : mod.serialize(op.doc))));
`

func runJS(t *testing.T, module string, ops []map[string]any) []json.RawMessage {
	abs, _ := filepath.Abs(module)
	in, _ := json.Marshal(map[string]any{"module": abs, "ops": ops})
	cmd := exec.Command("node", "-e", jsRunner)
	cmd.Stdin = bytes.NewReader(in)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("node: %v", err)
	}
	var res []json.RawMessage
	if err := json.Unmarshal(out, &res); err != nil {
		t.Fatal(err)
	}
	return res
}
