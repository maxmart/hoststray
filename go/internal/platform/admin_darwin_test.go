package platform

import (
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// These tests run the real admin prompts and need someone to type the
// password: HOSTSTRAY_ADMIN_TESTS=1 go test -run Admin -v ./internal/platform/
// They only touch a throwaway file and a throwaway CA.

func adminTests(t *testing.T) {
	if os.Getenv("HOSTSTRAY_ADMIN_TESTS") == "" {
		t.Skip("set HOSTSTRAY_ADMIN_TESTS=1 to run (needs your password)")
	}
}

func owner(t *testing.T, p string) uint32 {
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Sys().(*syscall.Stat_t).Uid
}

func TestAdminHostsFlows(t *testing.T) {
	adminTests(t)
	dir := t.TempDir()
	hosts := filepath.Join(dir, "hosts")
	os.Chmod(dir, 0o555) // we can't create files here, so writes need elevation
	t.Cleanup(func() { os.Chmod(dir, 0o755); os.Remove(hosts) })

	// 1. Cancelled prompt (clicked away automatically).
	go func() {
		time.Sleep(2500 * time.Millisecond)
		exec.Command("osascript", "-e", `tell application "System Events" to tell process "SecurityAgent" to click button "Cancel" of window 1`).Run()
	}()
	elevated, err := ElevatedWrite(hosts, []byte("cancelled\n"))
	if !elevated || !errors.Is(err, ErrCancelled) {
		t.Fatalf("cancel: elevated=%v err=%v", elevated, err)
	}
	if _, err := os.Stat(hosts); !os.IsNotExist(err) {
		t.Fatal("file written despite cancel")
	}

	// 2. Elevated write (password prompt).
	t.Log("PROMPT 1: enter your password")
	if elevated, err = ElevatedWrite(hosts, []byte("one\n")); err != nil || !elevated {
		t.Fatalf("elevated write: %v %v", elevated, err)
	}
	b, err := os.ReadFile(hosts)
	if err != nil || string(b) != "one\n" || owner(t, hosts) != 0 {
		t.Fatalf("after elevated write: %q %v owner=%d", b, err, owner(t, hosts))
	}
	if Writable(hosts) {
		t.Fatal("root-owned file writable before granting access")
	}

	// 3. Grant write access (password prompt); writes then go direct.
	t.Log("PROMPT 2: enter your password")
	if err := SetUserWritable(hosts, true); err != nil {
		t.Fatal(err)
	}
	if !Writable(hosts) {
		t.Fatal("not writable after granting")
	}
	if elevated, err = ElevatedWrite(hosts, []byte("two\n")); err != nil || elevated {
		t.Fatalf("direct write after grant: %v %v", elevated, err)
	}
	if b, _ := os.ReadFile(hosts); string(b) != "two\n" || owner(t, hosts) != 0 {
		t.Fatal("direct write wrong or changed owner")
	}

	// 4. Revoke (password prompt).
	t.Log("PROMPT 3: enter your password")
	if err := SetUserWritable(hosts, false); err != nil {
		t.Fatal(err)
	}
	if Writable(hosts) {
		t.Fatal("still writable after revoking")
	}
}

func TestAdminTrustCA(t *testing.T) {
	adminTests(t)
	ca := newTestCA(t)
	if trusted(ca) {
		t.Fatal("throwaway CA trusted before installing")
	}
	t.Log("PROMPT 4: macOS asks to change certificate trust settings; enter your password")
	if err := TrustCA(ca.path); err != nil {
		t.Fatal(err)
	}
	defer func() {
		t.Log("PROMPT 5: macOS asks to remove the trust setting; enter your password")
		if out, err := exec.Command("security", "remove-trusted-cert", ca.path).CombinedOutput(); err != nil {
			t.Errorf("remove trust: %v %s", err, out)
		}
		sum := sha1.Sum(ca.cert.Raw)
		exec.Command("security", "delete-certificate", "-Z", hex.EncodeToString(sum[:]), loginKeychain()).Run()
	}()
	if !trusted(ca) {
		t.Fatal("CA not trusted by the system after TrustCA")
	}
}

type testCA struct {
	path string
	cert *x509.Certificate
	leaf *x509.Certificate
}

func trusted(ca testCA) bool {
	_, err := ca.leaf.Verify(x509.VerifyOptions{DNSName: "admin-test.hoststray.invalid", KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
	return err == nil
}

// newTestCA uses openssl so this package doesn't depend on internal/certs.
func newTestCA(t *testing.T) testCA {
	dir := t.TempDir()
	run := func(args ...string) {
		if out, err := exec.Command("openssl", args...).CombinedOutput(); err != nil {
			t.Fatalf("openssl %v: %s", args, out)
		}
	}
	ca, key := filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")
	run("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", key, "-out", ca,
		"-days", "2", "-subj", "/CN=Hosts Tray admin test CA (delete me)",
		"-addext", "basicConstraints=critical,CA:true", "-addext", "keyUsage=critical,keyCertSign,cRLSign")
	lkey, csr, leaf := filepath.Join(dir, "l.key"), filepath.Join(dir, "l.csr"), filepath.Join(dir, "l.crt")
	run("req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", lkey, "-out", csr, "-subj", "/CN=admin-test.hoststray.invalid")
	ext := filepath.Join(dir, "ext")
	os.WriteFile(ext, []byte("subjectAltName=DNS:admin-test.hoststray.invalid\nextendedKeyUsage=serverAuth\n"), 0o644)
	run("x509", "-req", "-in", csr, "-CA", ca, "-CAkey", key, "-CAcreateserial", "-out", leaf, "-days", "1", "-extfile", ext)
	parse := func(p string) *x509.Certificate {
		b, _ := os.ReadFile(p)
		block, _ := pem.Decode(b)
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	return testCA{path: ca, cert: parse(ca), leaf: parse(leaf)}
}
