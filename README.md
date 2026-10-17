# Hosts Tray

A small tray app for developers who point real domain names at local services.
It toggles groups of entries in your hosts file and runs a local HTTPS proxy
with auto-generated certificates, so `https://app.example.com` can hit your
dev server on `localhost:3000` without browser warnings. Coding agents can
drive it too, through a skill file and its local API.

macOS and Windows. A single native binary written in Go: the macOS download
is under 9 MB.

## Why

Testing cookies, CORS, OAuth callbacks, or service workers usually needs the
real hostname over HTTPS. SwitchHosts is great but does not have an HTTPS
proxy built in.

Doing that by hand means editing an admin-owned hosts file, generating certs,
and running a reverse proxy. Hosts Tray wraps all three in a tray icon.

## Features

- **Hosts groups.** Mark sections of your hosts file with `#==== Name` and
  toggle each group on or off from the tray menu.
- **Hosts editor.** Edit entries in your browser instead of a text editor.
- **HTTPS proxy.** Listens on port 443, issues a certificate per hostname on
  the fly from a local CA, and forwards to whatever you configure, websockets
  included.
- **Route config.** Send web traffic and websocket upgrades to different ports
  by path prefix. Changes apply as soon as you save.
- **Trusted CA.** Offers to trust the generated root CA for your user account.
- **Agent skill.** Agents can list groups and switch groups and the proxy.
- **No password prompts, if you want.** One opt-in setting lets your account
  edit the hosts file, so toggles don't ask for a password.
- **Auto-update** from GitHub Releases.

## Install

Download from the [latest release](https://github.com/maxmart/hoststray/releases/latest):

- **macOS**: `Hosts-Tray-<version>.pkg` installs to Applications. The
  `-mac.zip` contains the same app if you'd rather drag it there yourself.
- **Windows**: `hoststray-<version>-windows-amd64.exe` (or `arm64`). Put it
  anywhere and run it.

The app lives in the menu bar (macOS) or the notification area (Windows);
there's no window or Dock icon.

## Hosts file groups

Groups are delimited by `#====` markers. An opening marker carries the name,
an empty one closes the group. Everything else in the file is left untouched.

```
#==== Staging
127.0.0.1  app.example.com
127.0.0.1  api.example.com
#====

#==== Customer demo
#127.0.0.1  demo.example.com
#====
```

Each group appears as a checkbox in the tray menu. Unchecking comments out
every entry in the group; checking uncomments them. A group counts as enabled
only when all of its entries are.

Only IPv4 entries are managed. Comments, blank lines, and anything else are
preserved byte for byte when the file is rewritten.

**Edit hosts…** opens the editor in your browser. It's served by the app on
`127.0.0.1` and only works through the link from the tray menu.

### Passwords

The hosts file belongs to the system, so changing it needs admin rights. By
default every change asks for your password (macOS) or a UAC confirmation
(Windows). **Settings → Change hosts without password** instead gives your
user account write access to the hosts file once, so later toggles, including
ones from agents, don't prompt. The app offers this after the first prompted
change. The trade-off: other programs running as you could then edit the
hosts file too.

## HTTPS proxy

Turn on **HTTPS proxy on :443** in the tray menu. The icon turns green while
the proxy runs, and it stays on across restarts until you turn it off.

On first start the app creates a root CA and offers to trust it for your user
account (macOS asks for your password; Windows asks you to confirm). Each
hostname that connects gets its own certificate signed by that CA, so any name
you point at `127.0.0.1` in the hosts file works immediately.

Forwarded requests carry `X-Forwarded-Proto: https`, `X-Forwarded-Port`,
`X-Forwarded-Host` and `X-Forwarded-For`, so your backend can build correct
absolute URLs.

### Routes

Routes live in `proxy.conf` in the app's data folder and are edited from
**Edit proxy routes…** in the tray menu. One rule per line:

```
# <pattern> -> <target>
* -> :80                       # all HTTPS traffic to 127.0.0.1:80
wss://*/socket -> :5124        # websocket upgrades under /socket to :5124
https://*/api -> 10.0.0.5:8080 # a path prefix to another host
```

- A target of `:PORT` means `127.0.0.1:PORT`. `host:PORT` picks a specific host.
- Patterns starting with `ws://` or `wss://` match websocket upgrades only.
  Upgrades that match no websocket route use the web routes.
- When several routes match, the longest path prefix wins. `*` is the catch-all.

## Agents

Coding agents drive Hosts Tray over its local HTTP API, guided by a skill
file. Install it for Claude Code with **Settings → Install agent skill**,
which writes `~/.claude/skills/hoststray/SKILL.md`. Other agents can read the
same file from `http://127.0.0.1:47443/SKILL.md`. No MCP or other setup is
needed.

The skill tells the agent to read a token from `token` in the data folder and
call these endpoints with it:

| Endpoint | What it does |
| --- | --- |
| `GET /api/status` | Groups with their entries, proxy state, port, CA trust, routes |
| `POST /api/group` `{"name","enabled"}` | Switch an existing group on or off |
| `POST /api/proxy/enabled` `{"enabled"}` | Start or stop the proxy |

The agent token is new on each launch and only works for those three. The
editors use a separate token that never touches disk, so agents can't add
hostnames, groups or routes, or trust the CA. Pointing a real domain at
localhost behind a trusted CA lets whoever controls it intercept that site's
traffic, so those stay with you in the editors. The server only answers on
`127.0.0.1` and rejects requests from web pages, so websites can't reach it.

## Updates

The app checks the latest GitHub release at launch and every six hours. When
there's a newer version it downloads it, checks it against the release's
`SHA256SUMS`, and on macOS also checks that it's signed by the same Apple team
as the running app. Then it offers to restart. An app installed by the `.pkg`
is owned by root, so installing the update asks for your password.
**Settings → Check for updates** checks right away.

## Data and logs

Settings, `proxy.conf`, the CA (`_certs/`) and `hoststray.log` live in
`~/Library/Application Support/hoststray` (macOS) or `%AppData%\hoststray`
(Windows). **Settings → Show data folder** opens it.

## Environment variables

| Variable | Default | Purpose |
| --- | --- | --- |
| `PORT` | `443` | Proxy port |
| `LISTEN_HOST` | all interfaces | Proxy listen address, e.g. `127.0.0.1` |
| `FORWARD_HOST` | `127.0.0.1` | Default target host for routes without one |
| `PROXY_TIMEOUT` | `300` | Upstream response timeout in seconds |
| `HOSTS_PATH` | system hosts file | Work on a copy instead; opens the editor at launch |
| `OPEN_PROXY_EDITOR` | unset | Open the routes editor at launch |
| `HOSTSTRAY_ADMIN_PORT` | `47443` | Port for the editors and API |
| `HOSTSTRAY_DATA_DIR` | see above | Data folder |
| `HOSTSTRAY_UPDATE_URL` | GitHub latest release | Release feed, for testing updates |

`--headless` runs without a tray icon (editors, API and proxy still work).

## Development

Needs Go 1.27 or newer; on macOS, Xcode command line tools (the tray uses cgo).

```sh
go run .                         # run from source
go test ./...                    # unit and integration tests
```

To try things without touching the real hosts file, copy it somewhere and run
with `HOSTS_PATH` pointing at the copy.

The hosts and `proxy.conf` parsers were ported from the original JavaScript
version; `internal/*/testdata/js_golden.json` holds that version's output for 800 inputs
each, and the tests check the Go port produces exactly the same.

Two opt-in macOS test suites need someone at the screen:

- `HOSTSTRAY_UI_TESTS=1 go test ./internal/platform/` clicks real dialogs.
- `HOSTSTRAY_ADMIN_TESTS=1 go test -run Admin ./internal/platform/` runs the
  password prompts (elevated write, password-free on/off, CA trust) against a
  throwaway file and CA. You type your password five times.

## Releasing

```sh
VERSION=0.11.0 ./scripts/build-release.sh   # build everything into dist/
VERSION=0.11.0 ./scripts/release.sh         # publish dist/ as a GitHub release (gh CLI)
```

`build-release.sh` produces `Hosts-Tray-<v>-mac.zip` and `.pkg` (universal,
signed and notarized, via `scripts/build-mac.sh`),
`hoststray-<v>-windows-{amd64,arm64}.exe` with icon and manifest, and the
`SHA256SUMS` the updater requires.

macOS signing needs, in your keychain, a **Developer ID Application**
certificate (and **Developer ID Installer** for the `.pkg`), plus an
app-specific password for notarization. Copy `.env.example` to `.env` and fill
it in. Without it, `build-mac.sh` builds an ad-hoc signed app for local use;
`NOTARIZE=0` signs without notarizing, for quick test builds.

The Windows executables are not code-signed yet, so SmartScreen warns on
first run.

## License

[MIT](LICENSE)
