// Package difftest runs the original JavaScript models (hosts-model.js,
// proxy-config.js) so tests can check the Go ports against them.
package difftest

import (
	"bytes"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// RepoRoot is the Electron repo root (the parent of the go/ module).
func RepoRoot() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "..")
}

const script = `
const input = JSON.parse(require("fs").readFileSync(0, "utf8"));
const mod = require(input.module);
const out = input.ops.map(op => {
  if (op.kind === "parse") return mod.parse(op.text);
  if (op.kind === "serialize") return mod.serialize(op.doc);
  if (op.kind === "parseEntry") return mod.parseEntry(op.text);
  throw new Error("bad op " + op.kind);
});
process.stdout.write(JSON.stringify(out));
`

// Run applies ops with the JS module and returns one raw JSON result per op.
// The test is skipped if node isn't available.
func Run(t *testing.T, module string, ops []map[string]any) []json.RawMessage {
	t.Helper()
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node not installed; skipping differential test")
	}
	in, _ := json.Marshal(map[string]any{"module": filepath.Join(RepoRoot(), module), "ops": ops})
	cmd := exec.Command("node", "-e", script)
	cmd.Stdin = bytes.NewReader(in)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("node: %v\n%s", err, stderr.String())
	}
	var res []json.RawMessage
	if err := json.Unmarshal(out, &res); err != nil {
		t.Fatal(err)
	}
	return res
}

// Normalize re-encodes JSON so key order and spacing don't matter.
func Normalize(t *testing.T, b []byte) string {
	t.Helper()
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatalf("normalize: %v (%s)", err, b)
	}
	out, _ := json.Marshal(v)
	return string(out)
}
