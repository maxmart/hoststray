package proxyconf

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

const sample = "# routes\n\n* -> :80\nwss://*/socket -> :5124\nhttps://*/api -> 10.0.0.5:8080\nws://*/cmweb ->  :5125  \nbad -> nope\n"

func TestParseAndRoutes(t *testing.T) {
	cfg := Parse(sample)
	if Serialize(cfg) != sample {
		t.Fatal("round trip changed")
	}
	web, ws := Routes(cfg, "")
	wantWeb := []Route{{PathPrefix: "", Host: "127.0.0.1", Port: 80}, {PathPrefix: "/api", Host: "10.0.0.5", Port: 8080}}
	wantWS := []Route{{WS: true, PathPrefix: "/socket", Host: "127.0.0.1", Port: 5124}, {WS: true, PathPrefix: "/cmweb", Host: "127.0.0.1", Port: 5125}}
	if !equal(web, wantWeb) || !equal(ws, wantWS) {
		t.Fatalf("routes: %+v %+v", web, ws)
	}
	web, _ = Routes(cfg, "192.168.1.2")
	if web[0].Host != "192.168.1.2" || web[1].Host != "10.0.0.5" {
		t.Fatalf("forward host: %+v", web)
	}
}

func equal(a, b []Route) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}

func TestEnsureFile(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "sub")
	p, err := EnsureFile(dir)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	if string(b) != DefaultConf {
		t.Fatal("default content")
	}
	os.WriteFile(p, []byte("* -> :1"), 0o644)
	EnsureFile(dir)
	if b, _ := os.ReadFile(p); string(b) != "* -> :1" {
		t.Fatal("existing file overwritten")
	}
}

func randomConf(r *rand.Rand) string {
	pats := []string{"*", "wss://*/s", "ws://*/a/b", "https://*/api", "HTTP://host/x", "x://", "*/p", "", " * ", "#c", "# * -> :1"}
	tgts := []string{":80", "  :5124 ", "10.0.0.1:81", "host:", ":", "1.2.3.4", "abc", ":0", ":99999", ": 12", ":+7", ":-3", "[::1]:80", "h:p:9"}
	var lines []string
	for i := r.Intn(15); i >= 0; i-- {
		switch r.Intn(5) {
		case 0:
			lines = append(lines, pats[r.Intn(len(pats))])
		default:
			lines = append(lines, pats[r.Intn(len(pats))]+[]string{" -> ", "->", " ->"}[r.Intn(3)]+tgts[r.Intn(len(tgts))])
		}
	}
	eol := "\n"
	if r.Intn(4) == 0 {
		eol = "\r\n"
	}
	return strings.Join(lines, eol)
}

func TestMatchesJS(t *testing.T) {
	r := rand.New(rand.NewSource(2))
	texts := []string{sample, DefaultConf, ""}
	for i := 0; i < 400; i++ {
		texts = append(texts, randomConf(r))
	}
	var ops []map[string]any
	for _, s := range texts {
		ops = append(ops, map[string]any{"kind": "parse", "text": s})
	}
	var edited []*Config
	for _, s := range texts {
		cfg := Parse(s)
		for _, n := range cfg.Nodes {
			if n.T == "route" && r.Intn(2) == 0 {
				n.Raw = nil
				n.WS = r.Intn(2) == 0
				n.Proto = []string{"", "ws", "https"}[r.Intn(3)]
				n.TargetHost = []string{"127.0.0.1", "", "other"}[r.Intn(3)]
				n.HostPattern = []string{"*", ""}[r.Intn(2)]
			}
		}
		edited = append(edited, cfg)
		ops = append(ops, map[string]any{"kind": "serialize", "doc": cfg})
	}
	res := golden(t, ops)
	for i, s := range texts {
		got, _ := json.Marshal(Parse(s))
		if normalize(t, got) != normalize(t, res[i]) {
			t.Errorf("parse mismatch for %q\n go: %s\n js: %s", s, got, res[i])
		}
	}
	for i, cfg := range edited {
		var js string
		json.Unmarshal(res[len(texts)+i], &js)
		if got := Serialize(cfg); got != js {
			t.Errorf("serialize mismatch\n go: %q\n js: %q", got, js)
		}
	}
}

// The expected results were produced by the original JavaScript
// implementation (proxy-config.js) when the Go port replaced it. Regenerate only with a
// copy of that file: go test -run MatchesJS -update-golden=<path to proxy-config.js>
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
