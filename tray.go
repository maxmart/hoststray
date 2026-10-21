package main

import (
	"context"
	"fmt"
	"log"
	"reflect"
	"sync"
	"time"

	"fyne.io/systray"

	"github.com/maxmart/hoststray/internal/app"
	"github.com/maxmart/hoststray/internal/hosts"
	"github.com/maxmart/hoststray/internal/platform"
)

// menuState is everything the menu shows; the menu is rebuilt only when it
// changes, so an open menu isn't yanked away by a no-op refresh.
type menuState struct {
	Groups       []hosts.Group
	HostsErr     string
	ProxyOn      bool
	Trusted      bool
	GroupHelper  bool
	Writable     bool
	LoginItem    bool
	Update       string
}

type tray struct {
	app *app.App

	mu      sync.Mutex
	state   *menuState
	cancel  context.CancelFunc
	proxy   *systray.MenuItem // the switches, for in-place updates
	groups  map[string]*systray.MenuItem
	trusted bool
	checked time.Time // when trust was last checked
}

func runTray(a *app.App) {
	t := &tray{app: a}
	a.SetQuit(t.quit)
	systray.Run(t.onReady, a.Shutdown)
}

// quit cleans up before telling the tray to exit: on macOS the process ends
// before systray's exit callback gets to run, which left the agent token file
// behind.
func (t *tray) quit() {
	t.app.Shutdown()
	systray.Quit()
}

func (t *tray) onReady() {
	systray.SetTooltip("Hosts Tray")
	watchMenu()
	t.refresh(true)
	t.app.OnChange(func() { t.refresh(true) })

	// Pick up hosts file edits made elsewhere, and trust changes made by hand.
	go func() {
		for range time.Tick(2 * time.Second) {
			t.refresh(false)
		}
	}()
}

func (t *tray) current(recheckTrust bool) *menuState {
	t.mu.Lock()
	if recheckTrust || time.Since(t.checked) > 30*time.Second {
		t.trusted = t.app.CA.Trusted()
		t.checked = time.Now()
	}
	trusted := t.trusted
	t.mu.Unlock()

	s := &menuState{ProxyOn: t.app.ProxyRunning(), Trusted: trusted,
		GroupHelper: t.app.GroupHelper(), Writable: t.app.HostsWritable(), LoginItem: platform.LoginItemEnabled()}
	if p := t.app.PendingUpdate(); p != nil {
		s.Update = p.Version
	}
	groups, err := t.app.Groups()
	if err != nil {
		s.HostsErr = err.Error()
	}
	s.Groups = groups
	return s
}

func (t *tray) refresh(recheckTrust bool) {
	s := t.current(recheckTrust)
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.state != nil && reflect.DeepEqual(*t.state, *s) {
		return
	}
	// Only switches changed: update them in place. Rebuilding an open menu
	// makes it flicker, and macOS closes a menu that is briefly empty.
	if t.state != nil && reflect.DeepEqual(structure(t.state), structure(s)) {
		t.state = s
		t.update(s)
		return
	}
	t.state = s
	if t.cancel != nil {
		t.cancel() // stop listening on the previous menu's items
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.cancel = cancel
	t.build(ctx, s)
}

// structure is the menu state without the switch positions: if it is
// unchanged, the menu can be updated in place instead of rebuilt.
func structure(s *menuState) menuState {
	c := *s
	c.ProxyOn = false
	c.Groups = make([]hosts.Group, len(s.Groups))
	for i, g := range s.Groups {
		g.Enabled = false
		g.Entries = append([]hosts.Entry(nil), g.Entries...)
		for j := range g.Entries {
			g.Entries[j].Enabled = false
		}
		c.Groups[i] = g
	}
	return c
}

// update moves the switches to the new state without rebuilding the menu.
func (t *tray) update(s *menuState) {
	setProxyIcon(s.ProxyOn)
	items, on := []*systray.MenuItem{t.proxy}, []bool{s.ProxyOn}
	for _, g := range s.Groups {
		if item := t.groups[g.Name]; item != nil {
			items, on = append(items, item), append(on, g.Enabled)
		}
	}
	setSwitches(items, on)
}

func check(item *systray.MenuItem, on bool) {
	if on {
		item.Check()
	} else {
		item.Uncheck()
	}
}

func setProxyIcon(on bool) {
	systray.SetIcon(trayIcon(on))
	if on {
		systray.SetTooltip("Hosts Tray - Proxy ON")
	} else {
		systray.SetTooltip("Hosts Tray - Proxy OFF")
	}
}

// on runs f in its own goroutine each time item is clicked, until ctx ends.
func on(ctx context.Context, item *systray.MenuItem, f func()) {
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-item.ClickedCh:
				go f()
			}
		}
	}()
}

func (t *tray) build(ctx context.Context, s *menuState) {
	a := t.app
	systray.ResetMenu()
	setProxyIcon(s.ProxyOn)

	systray.AddMenuItem("Hosts Tray "+version, "").Disable()
	if s.Update != "" {
		on(ctx, systray.AddMenuItem("Restart to update to "+s.Update, ""), func() { a.InstallUpdate() })
	}
	on(ctx, systray.AddMenuItem("Open Hosts Tray…", "Open the console in your browser"), func() {
		platform.OpenURL(a.ConsoleURL(""))
	})
	on(ctx, systray.AddMenuItem("Edit hosts…", "Open the hosts editor in your browser"), func() {
		platform.OpenURL(a.ConsoleURL("hosts"))
	})
	on(ctx, systray.AddMenuItem("Edit proxy routes…", "Open the proxy routes editor in your browser"), func() {
		platform.OpenURL(a.ConsoleURL("routes"))
	})
	systray.AddSeparator()

	proxyItem := systray.AddMenuItemCheckbox(fmt.Sprintf("HTTPS proxy on :%d", a.ProxyPort()), "", s.ProxyOn)
	switches := []*systray.MenuItem{proxyItem}
	t.proxy, t.groups = proxyItem, map[string]*systray.MenuItem{}
	on(ctx, proxyItem, t.keepOpen(func() error {
		err := a.SetProxy(!a.ProxyRunning())
		if err != nil {
			log.Printf("proxy: %v", err)
		}
		return err
	}))
	if !s.Trusted {
		on(ctx, systray.AddMenuItem("Trust the HTTPS certificate…", "Stop browser certificate warnings"), func() {
			a.OfferTrust()
			t.refresh(true)
		})
	}
	systray.AddSeparator()

	if s.HostsErr != "" {
		systray.AddMenuItem("Can't read hosts file", s.HostsErr).Disable()
	} else if len(s.Groups) == 0 {
		systray.AddMenuItem("No groups (add one with Edit hosts…)", "").Disable()
	}
	for _, g := range s.Groups {
		g := g
		item := systray.AddMenuItemCheckbox(g.Name, fmt.Sprintf("%d entries", len(g.Entries)), g.Enabled)
		switches = append(switches, item)
		t.groups[g.Name] = item
		on(ctx, item, t.keepOpen(func() error {
			// The menu may have been updated in place since it was built, so
			// flip the group's current state, not g.Enabled.
			_, err := a.SetGroup(g.Name, !t.app.GroupEnabled(g.Name))
			if err != nil {
				log.Printf("toggle %q: %v", g.Name, err)
			}
			return err
		}))
	}
	systray.AddSeparator()

	settings := systray.AddMenuItem("Settings", "")
	login := settings.AddSubMenuItemCheckbox("Launch at login", "", s.LoginItem)
	on(ctx, login, func() {
		if err := platform.SetLoginItem(!s.LoginItem); err != nil {
			platform.Alert("Hosts Tray", "Could not change the login item.\n\n"+err.Error())
		}
		t.refresh(false)
	})
	pw := settings.AddSubMenuItemCheckbox("Switch groups without password", "Installs a small helper", s.GroupHelper)
	on(ctx, pw, func() { a.SetHostsPasswordless(!s.GroupHelper) })
	if platform.IsSystemHosts(a.Config().HostsPath) {
		edit := settings.AddSubMenuItemCheckbox("Edit hosts without password", "Any program running as you could edit it too", s.Writable)
		on(ctx, edit, func() { a.SetHostsWritable(!s.Writable) })
	}
	on(ctx, settings.AddSubMenuItem("Install agent skill", "For Claude Code; other agents can read "+a.BaseURL()+"/SKILL.md"), func() {
		path, err := a.InstallSkill()
		if err != nil {
			platform.Alert("Hosts Tray", "Could not install the skill.\n\n"+err.Error())
			return
		}
		msg := "Installed the Hosts Tray skill for Claude Code:\n\n" + path +
			"\n\nOther agents can read it from " + a.BaseURL() + "/SKILL.md"
		if !a.StandardSetup() {
			msg += "\n\nThis is a test setup (custom port or data folder), and the skill points at it. " +
				"Starting Hosts Tray normally will update it."
		}
		platform.Alert("Hosts Tray", msg)
	})
	on(ctx, settings.AddSubMenuItem("Check for updates", ""), func() { a.CheckForUpdates(true) })
	on(ctx, settings.AddSubMenuItem("Show data folder", a.Config().DataDir), func() {
		platform.OpenURL(a.Config().DataDir)
	})
	systray.AddSeparator()

	on(ctx, systray.AddMenuItem("Quit", ""), t.quit)
	useSwitches(switches)
}

// keepOpen runs a switch from the menu and then reopens the menu, so several
// can be flipped in a row. Not after an error, or when the switch took long
// enough that a password prompt or dialog probably came up in between.
func (t *tray) keepOpen(f func() error) func() {
	return func() {
		start := time.Now()
		if err := f(); err != nil {
			// A switch flips as soon as it is clicked; put it back.
			t.mu.Lock()
			s := t.state
			t.mu.Unlock()
			if s != nil {
				t.update(s)
			}
			return
		}
		if time.Since(start) > 2*time.Second {
			return
		}
		t.refresh(false) // show the new state, not the one the menu was built with
		reopenMenu()
	}
}
