// Package certs is a tiny local certificate authority. It issues one leaf
// certificate per hostname on demand, signed by a root CA that the user trusts.
package certs

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// File names are kept from the Electron version so its CA keeps working.
const caName = "ssl.proxy.hoststray.cupmanager.net"

const (
	leafValidity = 800 * 24 * time.Hour // Apple rejects TLS leaf certs over 825 days
	maxValidity  = 825 * 24 * time.Hour
	renewBefore  = 30 * 24 * time.Hour
)

// validName limits SNI names to hostname characters: they become file names.
var validName = regexp.MustCompile(`^[a-z0-9_]([a-z0-9_.-]{0,251}[a-z0-9_])?$`)

type Authority struct {
	dir    string
	cert   *x509.Certificate
	key    crypto.Signer
	certPE []byte

	mu    sync.Mutex
	cache map[string]*tls.Certificate
}

// Open loads the CA from dir, creating one if it doesn't exist. created
// reports whether a new CA was generated (and so isn't trusted yet).
func Open(dir string) (a *Authority, created bool, err error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, false, err
	}
	a = &Authority{dir: dir, cache: map[string]*tls.Certificate{}}
	certPEM, err1 := os.ReadFile(a.CertPath())
	keyPEM, err2 := os.ReadFile(filepath.Join(dir, caName+".key"))
	if err1 == nil && err2 == nil {
		if err := a.load(certPEM, keyPEM); err != nil {
			return nil, false, fmt.Errorf("load CA: %w", err)
		}
		return a, false, nil
	}
	if !os.IsNotExist(err1) && err1 != nil {
		return nil, false, err1
	}
	if err := a.create(); err != nil {
		return nil, false, fmt.Errorf("create CA: %w", err)
	}
	return a, true, nil
}

// CertPath is the CA certificate (PEM), for installing into trust stores.
func (a *Authority) CertPath() string { return CAPath(a.dir) }

// CAPath is where Open keeps the CA certificate in dir, without creating it.
func CAPath(dir string) string { return filepath.Join(dir, caName+".crt") }

func (a *Authority) Cert() *x509.Certificate { return a.cert }

func (a *Authority) load(certPEM, keyPEM []byte) error {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return errors.New("no PEM certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	key, err := parseKey(keyPEM)
	if err != nil {
		return err
	}
	a.cert, a.key, a.certPE = cert, key, certPEM
	return nil
}

func parseKey(keyPEM []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, errors.New("no PEM key")
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	if k, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	s, ok := k.(crypto.Signer)
	if !ok {
		return nil, errors.New("unsupported key type")
	}
	return s, nil
}

func serial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	return n
}

func (a *Authority) create() error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	host, _ := os.Hostname()
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: "Hosts Tray Local CA (" + host + ")", Organization: []string{"Hosts Tray"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(filepath.Join(a.dir, caName+".key"), keyPEM, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(a.CertPath(), certPEM, 0o644); err != nil {
		return err
	}
	return a.load(certPEM, keyPEM)
}

// GetCertificate is a tls.Config.GetCertificate callback.
func (a *Authority) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	name := strings.TrimSuffix(strings.ToLower(hello.ServerName), ".")
	if name == "" {
		name = "localhost" // no SNI, e.g. https://127.0.0.1
	}
	return a.Leaf(name)
}

// Leaf returns a certificate for name, from memory, disk, or freshly issued.
func (a *Authority) Leaf(name string) (*tls.Certificate, error) {
	if !validName.MatchString(name) || strings.Contains(name, "..") {
		return nil, fmt.Errorf("refusing certificate for invalid name %q", name)
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	if c := a.cache[name]; c != nil && a.usable(c.Leaf, name) {
		return c, nil
	}
	certPath := filepath.Join(a.dir, name+".crt")
	keyPath := filepath.Join(a.dir, name+".key")
	if c, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil && c.Leaf != nil && a.usable(c.Leaf, name) {
		c.Certificate = append(c.Certificate, a.cert.Raw)
		a.cache[name] = &c
		return &c, nil
	}
	c, certPEM, keyPEM, err := a.issue(name)
	if err != nil {
		return nil, err
	}
	// Disk cache is best effort.
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err == nil {
		os.WriteFile(certPath, certPEM, 0o644)
	}
	a.cache[name] = c
	return c, nil
}

// usable reports whether a leaf is signed by this CA, valid for name, not about
// to expire, and acceptable to macOS (serverAuth EKU, at most 825 days).
func (a *Authority) usable(leaf *x509.Certificate, name string) bool {
	if leaf == nil || leaf.CheckSignatureFrom(a.cert) != nil || leaf.VerifyHostname(name) != nil {
		return false
	}
	if leaf.NotAfter.Sub(leaf.NotBefore) > maxValidity || time.Until(leaf.NotAfter) < renewBefore {
		return false
	}
	for _, u := range leaf.ExtKeyUsage {
		if u == x509.ExtKeyUsageServerAuth {
			return true
		}
	}
	return false
}

func (a *Authority) issue(name string) (*tls.Certificate, []byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(-time.Hour).Add(leafValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{name},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, a.cert, key.Public(), a.key)
	if err != nil {
		return nil, nil, nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, nil, err
	}
	c := &tls.Certificate{Certificate: [][]byte{der, a.cert.Raw}, PrivateKey: key, Leaf: leaf}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return c, certPEM, keyPEM, nil
}

// Trusted reports whether the OS trusts this CA for TLS, by verifying a
// throwaway leaf against the system verifier (which honours user trust
// settings on macOS and the user Root store on Windows).
func (a *Authority) Trusted() bool {
	const name = "trust-check.hoststray.invalid"
	c, _, _, err := a.issue(name)
	if err != nil {
		return false
	}
	_, err = c.Leaf.Verify(x509.VerifyOptions{DNSName: name, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
	return err == nil
}

// SameCA reports whether pemBytes holds this CA's certificate.
func (a *Authority) SameCA(pemBytes []byte) bool {
	block, _ := pem.Decode(pemBytes)
	return block != nil && bytes.Equal(block.Bytes, a.cert.Raw)
}
