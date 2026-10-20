// Package app holds Hosts Tray's state and the operations shared by the tray
// menu, the browser editors and agents.
package app

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/maxmart/hoststray/internal/certs"
	"github.com/maxmart/hoststray/internal/hosts"
	"github.com/maxmart/hoststray/internal/platform"
	"github.com/maxmart/hoststray/internal/proxy"
	"github.com/maxmart/hoststray/internal/proxyconf"
)

type Settings struct {
	ProxyEnabled         bool `json:"proxyEnabled"`
	PasswordlessDeclined bool `json:"passwordlessDeclined"`
	TrustDeclined        bool `json:"trustDeclined"`
}

type Config struct {
	Version     string
	DataDir     string
	HostsPath   string
	ProxyPort   int
	ListenHost  string
	ForwardHost string
	Timeout     time.Duration
	AdminPort   int
	// Interactive is false in headless mode and tests: no dialogs are shown.
	Interactive bool
}

// ConfigFromEnv reads the configuration from environment variables.
func ConfigFromEnv(version string) Config {
	c := Config{
		Version:     version,
		DataDir:     platform.DataDir(),
		HostsPath:   platform.HostsPath(),
		ProxyPort:   envInt("PORT", 443),
		ListenHost:  os.Getenv("LISTEN_HOST"),
		ForwardHost: os.Getenv("FORWARD_HOST"),
		Timeout:     time.Duration(envInt("PROXY_TIMEOUT", 300)) * time.Second,
		AdminPort:   envInt("HOSTSTRAY_ADMIN_PORT", 47443),
		Interactive: true,
	}
	return c
}

func envInt(name string, def int) int {
	if n, err := strconv.Atoi(os.Getenv(name)); err == nil && n > 0 {
		return n
	}
	return def
}

type App struct {
	cfg      Config
	CA       *certs.Authority
	proxy    *proxy.Server
	confPath string
	token    string // editors: full API
	agentTok string // agents: status, groups, proxy on/off

	mu       sync.Mutex // serializes hosts/proxy.conf writes and settings
	settings Settings

	listenersMu sync.Mutex
	listeners   []func()

	pending *UpdateReady // guarded by mu
	quit    func()
}

func New(cfg Config) (*App, error) {
	if err := os.MkdirAll(cfg.DataDir, 0o755); err != nil {
		return nil, err
	}
	ca, _, err := certs.Open(filepath.Join(cfg.DataDir, "_certs"))
	if err != nil {
		return nil, err
	}
	confPath, err := proxyconf.EnsureFile(cfg.DataDir)
	if err != nil {
		return nil, err
	}
	tok := make([]byte, 16)
	rand.Read(tok)
	token := hex.EncodeToString(tok)
	if t := os.Getenv("HOSTSTRAY_TOKEN"); len(t) >= 16 {
		token = t // fixed token for automated testing of the editors
	}
	agentTok := make([]byte, 16)
	rand.Read(agentTok)
	a := &App{cfg: cfg, CA: ca, confPath: confPath, token: token, agentTok: hex.EncodeToString(agentTok)}
	a.proxy = proxy.New(proxy.Options{CA: ca, ListenHost: cfg.ListenHost, Port: cfg.ProxyPort, Timeout: cfg.Timeout})
	a.loadSettings()
	return a, nil
}

func (a *App) Config() Config { return a.cfg }

// Token authorizes the browser editors' API calls.
func (a *App) Token() string { return a.token }

// OnChange registers a callback for state changes (hosts, proxy, settings).
func (a *App) OnChange(f func()) {
	a.listenersMu.Lock()
	a.listeners = append(a.listeners, f)
	a.listenersMu.Unlock()
}

func (a *App) changed() {
	a.listenersMu.Lock()
	ls := append([]func(){}, a.listeners...)
	a.listenersMu.Unlock()
	for _, f := range ls {
		f()
	}
}

// --- settings -----------------------------------------------------------------

func (a *App) settingsPath() string { return filepath.Join(a.cfg.DataDir, "settings.json") }

func (a *App) loadSettings() {
	if b, err := os.ReadFile(a.settingsPath()); err == nil {
		json.Unmarshal(b, &a.settings)
	}
}

func (a *App) updateSettings(f func(*Settings)) {
	a.mu.Lock()
	f(&a.settings)
	b, _ := json.MarshalIndent(a.settings, "", "  ")
	a.mu.Unlock()
	if err := os.WriteFile(a.settingsPath(), b, 0o644); err != nil {
		log.Printf("settings write failed: %v", err)
	}
}

func (a *App) Settings() Settings {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.settings
}

// --- hosts --------------------------------------------------------------------

func (a *App) LoadHosts() (*hosts.Doc, error) {
	b, err := os.ReadFile(a.cfg.HostsPath)
	if err != nil {
		return nil, err
	}
	return hosts.Parse(string(b)), nil
}

func (a *App) Groups() ([]hosts.Group, error) {
	doc, err := a.LoadHosts()
	if err != nil {
		return nil, err
	}
	return hosts.Groups(doc), nil
}

type SaveResult struct {
	OK            bool   `json:"ok"`
	Elevated      bool   `json:"elevated,omitempty"`
	RestartNeeded bool   `json:"restartNeeded,omitempty"`
	Error         string `json:"error,omitempty"`
	err           error  // the cause of Error, for errors.Is
}

// SaveHosts writes the document, elevating if needed.
func (a *App) SaveHosts(doc *hosts.Doc) SaveResult {
	a.mu.Lock()
	elevated, err := platform.ElevatedWrite(a.cfg.HostsPath, []byte(hosts.Serialize(doc)))
	a.mu.Unlock()
	if err != nil {
		log.Printf("hosts write failed: %v", err)
		return SaveResult{Error: err.Error(), err: err}
	}
	a.proxy.DropKeepAlives() // so browsers look hostnames up again
	a.changed()
	if elevated {
		go a.offerPasswordless()
	}
	return SaveResult{OK: true, Elevated: elevated}
}

var ErrNoGroup = errors.New("no such group")

// GroupEnabled reports whether every entry of the named group is on.
func (a *App) GroupEnabled(name string) bool {
	groups, err := a.Groups()
	if err != nil {
		return false
	}
	for _, g := range groups {
		if g.Name == name {
			return g.Enabled
		}
	}
	return false
}

// SetGroup turns every entry in an existing group on or off.
func (a *App) SetGroup(name string, enable bool) (SaveResult, error) {
	doc, err := a.LoadHosts()
	if err != nil {
		return SaveResult{}, err
	}
	if !hosts.SetGroup(doc, name, enable) {
		return SaveResult{}, fmt.Errorf("%w %q", ErrNoGroup, name)
	}
	res := a.SaveHosts(doc)
	if !res.OK {
		return res, res.err
	}
	return res, nil
}

// HostsPasswordless reports whether hosts writes work without elevation.
func (a *App) HostsPasswordless() bool { return platform.Writable(a.cfg.HostsPath) }

func (a *App) SetHostsPasswordless(enable bool) error {
	err := platform.SetUserWritable(a.cfg.HostsPath, enable)
	a.changed()
	if err != nil && !errors.Is(err, platform.ErrCancelled) && a.cfg.Interactive {
		platform.Alert("Hosts Tray", "Could not change hosts file permissions.\n\n"+err.Error())
	}
	return err
}

// offerPasswordless asks once (after a password-prompted write) whether to
// skip the password from now on.
func (a *App) offerPasswordless() {
	if !a.cfg.Interactive || a.HostsPasswordless() || a.Settings().PasswordlessDeclined {
		return
	}
	msg := "Hosts Tray can give your user account write access to " + a.cfg.HostsPath +
		" so toggling groups no longer asks for your password. Other programs running as you could then edit it too.\n\n" +
		"You can change this later from the tray menu."
	switch platform.Ask("Change the hosts file without a password?", msg, "Allow", "Not now", "Don't ask again") {
	case 0:
		a.SetHostsPasswordless(true)
	case 2:
		a.updateSettings(func(s *Settings) { s.PasswordlessDeclined = true })
	}
}

// --- proxy --------------------------------------------------------------------

func (a *App) ProxyConfPath() string { return a.confPath }

func (a *App) LoadProxyConf() (*proxyconf.Config, error) {
	b, err := os.ReadFile(a.confPath)
	if err != nil {
		return nil, err
	}
	return proxyconf.Parse(string(b)), nil
}

// SaveProxyConf writes proxy.conf and applies it to a running proxy at once.
func (a *App) SaveProxyConf(cfg *proxyconf.Config) SaveResult {
	a.mu.Lock()
	err := os.WriteFile(a.confPath, []byte(proxyconf.Serialize(cfg)), 0o644)
	a.mu.Unlock()
	if err != nil {
		return SaveResult{Error: err.Error(), err: err}
	}
	a.applyRoutes(cfg)
	a.changed()
	return SaveResult{OK: true}
}

func (a *App) applyRoutes(cfg *proxyconf.Config) {
	web, ws := proxyconf.Routes(cfg, a.cfg.ForwardHost)
	a.proxy.SetRoutes(web, ws)
}

type Routes struct {
	Web []proxyconf.Route `json:"web"`
	WS  []proxyconf.Route `json:"websocket"`
}

func (a *App) Routes() (Routes, error) {
	cfg, err := a.LoadProxyConf()
	if err != nil {
		return Routes{}, err
	}
	web, ws := proxyconf.Routes(cfg, a.cfg.ForwardHost)
	return Routes{web, ws}, nil
}

func (a *App) ProxyRunning() bool { return a.proxy.Running() }

func (a *App) ProxyPort() int { return a.cfg.ProxyPort }

// SetProxy starts or stops the proxy and remembers the choice for next launch.
func (a *App) SetProxy(enable bool) error {
	defer a.changed()
	if !enable {
		a.proxy.Stop()
		a.updateSettings(func(s *Settings) { s.ProxyEnabled = false })
		return nil
	}
	cfg, err := a.LoadProxyConf()
	if err != nil {
		return err
	}
	a.applyRoutes(cfg)
	if err := a.proxy.Start(); err != nil {
		if a.cfg.Interactive {
			platform.Alert("HTTPS Proxy", fmt.Sprintf("The proxy could not listen on port %d.\n\n%v", a.cfg.ProxyPort, err))
		}
		return err
	}
	a.updateSettings(func(s *Settings) { s.ProxyEnabled = true })
	if a.cfg.Interactive && !a.Settings().TrustDeclined && !a.CA.Trusted() {
		go a.OfferTrust()
	}
	return nil
}

// RestoreProxy starts the proxy if it was on when the app last quit.
func (a *App) RestoreProxy() {
	if a.Settings().ProxyEnabled {
		if err := a.SetProxy(true); err != nil {
			log.Printf("proxy start failed: %v", err)
		}
	}
}

func (a *App) Shutdown() {
	a.proxy.Stop()
	a.removeToken()
}

// --- CA trust -------------------------------------------------------------------

// OfferTrust asks the user to trust the local CA, then installs it.
func (a *App) OfferTrust() {
	msg := "Browsers will show certificate warnings until your computer trusts the Hosts Tray certificate authority.\n\n" +
		"It only signs certificates for the hostnames you send through the proxy."
	if runtime.GOOS == "darwin" {
		msg += " macOS will ask for your password."
	}
	switch platform.Ask("Trust the Hosts Tray certificate?", msg, "Trust", "Not now", "Show command") {
	case 0:
		a.TrustCA()
	case 1:
		a.updateSettings(func(s *Settings) { s.TrustDeclined = true })
	case 2:
		cmd := platform.TrustCommand(a.CA.CertPath())
		platform.CopyToClipboard(cmd)
		platform.Alert("Trust the certificate yourself", "Run this command (copied to the clipboard):\n\n"+cmd)
	}
}

func (a *App) TrustCA() error {
	err := platform.TrustCA(a.CA.CertPath())
	defer a.changed()
	if !a.cfg.Interactive {
		return err
	}
	if err != nil {
		platform.Alert("Hosts Tray", "The certificate could not be trusted.\n\n"+err.Error()+
			"\n\nYou can run this yourself:\n"+platform.TrustCommand(a.CA.CertPath()))
		return err
	}
	a.updateSettings(func(s *Settings) { s.TrustDeclined = false })
	return nil
}

// --- status ---------------------------------------------------------------------

type Status struct {
	Version           string        `json:"version"`
	HostsPath         string        `json:"hostsPath"`
	HostsPasswordless bool          `json:"hostsPasswordless"`
	Groups            []hosts.Group `json:"groups"`
	Proxy             ProxyStatus   `json:"proxy"`
	UpdateReady       string        `json:"updateReady,omitempty"`
	LoginItem         bool          `json:"loginItem"`
	DataDir           string        `json:"dataDir"`
	SkillInstalled    bool          `json:"skillInstalled"`
}

type ProxyStatus struct {
	Running   bool   `json:"running"`
	Port      int    `json:"port"`
	CATrusted bool   `json:"caTrusted"`
	ConfPath  string `json:"confPath"`
	Routes    Routes `json:"routes"`
}

func (a *App) Status() (Status, error) {
	groups, err := a.Groups()
	if err != nil {
		return Status{}, err
	}
	routes, err := a.Routes()
	if err != nil {
		return Status{}, err
	}
	return Status{
		Version:           a.cfg.Version,
		HostsPath:         a.cfg.HostsPath,
		HostsPasswordless: a.HostsPasswordless(),
		Groups:            groups,
		Proxy: ProxyStatus{Running: a.ProxyRunning(), Port: a.cfg.ProxyPort, CATrusted: a.CA.Trusted(),
			ConfPath: a.confPath, Routes: routes},
		UpdateReady:    a.updateVersion(),
		LoginItem:      platform.LoginItemEnabled(),
		DataDir:        a.cfg.DataDir,
		SkillInstalled: skillInstalled(),
	}, nil
}

func (a *App) updateVersion() string {
	if p := a.PendingUpdate(); p != nil {
		return p.Version
	}
	return ""
}
