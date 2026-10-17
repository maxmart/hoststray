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
	Passwordless bool
	LoginItem    bool
	Update       string
}

type tray struct {
	app *app.App

	mu      sync.Mutex
	state   *menuState
	cancel  context.CancelFunc
	trusted bool
	checked time.Time // when trust was last checked
}

func runTray(a *app.App) {
	t := &tray{app: a}
	a.SetQuit(systray.Quit)
	systray.Run(t.onReady, a.Shutdown)
}

func (t *tray) onReady() {
	systray.SetTooltip("Hosts Tray")
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
		Passwordless: t.app.HostsPasswordless(), LoginItem: platform.LoginItemEnabled()}
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
	t.state = s
	if t.cancel != nil {
		t.cancel() // stop listening on the previous menu's items
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.cancel = cancel
	t.build(ctx, s)
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
	systray.SetIcon(trayIcon(s.ProxyOn))
	if s.ProxyOn {
		systray.SetTooltip("Hosts Tray - Proxy ON")
	} else {
		systray.SetTooltip("Hosts Tray - Proxy OFF")
	}

	systray.AddMenuItem("Hosts Tray "+version, "").Disable()
	if s.Update != "" {
		on(ctx, systray.AddMenuItem("Restart to update to "+s.Update, ""), func() { a.InstallUpdate() })
	}
	on(ctx, systray.AddMenuItem("Edit hosts…", "Open the hosts editor in your browser"), func() {
		platform.OpenURL(a.EditorURL("hosts"))
	})
	on(ctx, systray.AddMenuItem("Edit proxy routes…", "Open the proxy routes editor in your browser"), func() {
		platform.OpenURL(a.EditorURL("routes"))
	})
	systray.AddSeparator()

	proxyItem := systray.AddMenuItemCheckbox(fmt.Sprintf("HTTPS proxy on :%d", a.ProxyPort()), "", s.ProxyOn)
	on(ctx, proxyItem, func() {
		if err := a.SetProxy(!a.ProxyRunning()); err != nil {
			log.Printf("proxy: %v", err)
		}
	})
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
		on(ctx, item, func() {
			if _, err := a.SetGroup(g.Name, !g.Enabled); err != nil {
				log.Printf("toggle %q: %v", g.Name, err)
			}
		})
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
	pw := settings.AddSubMenuItemCheckbox("Change hosts without password", "", s.Passwordless)
	on(ctx, pw, func() { a.SetHostsPasswordless(!s.Passwordless) })
	on(ctx, settings.AddSubMenuItem("Copy MCP setup command", "For Claude Code; other agents use the URL "+a.MCPURL()), func() {
		cmd := "claude mcp add --transport http hoststray " + a.MCPURL()
		if err := platform.CopyToClipboard(cmd); err != nil {
			platform.Alert("Hosts Tray", "Add this MCP server to your agent:\n\n"+a.MCPURL())
		}
	})
	on(ctx, settings.AddSubMenuItem("Check for updates", ""), func() { a.CheckForUpdates(true) })
	on(ctx, settings.AddSubMenuItem("Show data folder", a.Config().DataDir), func() {
		platform.OpenURL(a.Config().DataDir)
	})
	systray.AddSeparator()

	on(ctx, systray.AddMenuItem("Quit", ""), systray.Quit)
}
