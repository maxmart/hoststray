package proxyconf

import (
	"encoding/json"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/maxmart/hoststray/internal/difftest"
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
	res := difftest.Run(t, "proxy-config.js", ops)
	for i, s := range texts {
		got, _ := json.Marshal(Parse(s))
		if difftest.Normalize(t, got) != difftest.Normalize(t, res[i]) {
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
