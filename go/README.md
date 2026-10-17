# Hosts Tray (Go)

A rewrite of Hosts Tray as a single native binary: about 10 MB instead of
Electron's 250 MB, with no bundled browser. It does everything the Electron
version does, plus an MCP server so coding agents can switch hosts groups and
the proxy.

- **Tray menu**: hosts groups as checkboxes, HTTPS proxy on/off, editors,
  settings. The icon turns green while the proxy runs.
- **Editors**: the same hosts and proxy-route editors, opened in your browser
  from a local server on `127.0.0.1:47443`.
- **HTTPS proxy**: per-hostname certificates from a local CA, path-prefix
  routing, websockets. Route changes apply immediately.
- **MCP**: `http://127.0.0.1:47443/mcp`, served by the tray app itself.
- **Auto-update** from GitHub Releases, checked at launch and every six hours.

It reads the Electron version's data folder (`proxy.conf`, the CA in
`_certs/`, `settings.json`), so an existing setup keeps working, including a
CA you already trust.

## MCP

Add it to Claude Code with **Settings → Copy MCP setup command** in the tray
menu, or:

```sh
claude mcp add --transport http hoststray http://127.0.0.1:47443/mcp
```

Tools:

| Tool | What it does |
| --- | --- |
| `get_status` | Groups with their entries, proxy state, port, CA trust, routes |
| `set_hosts_group` | Switch an existing group on or off |
| `set_proxy` | Start or stop the proxy |

Agents can't add hostnames, groups or routes, or trust the CA. Pointing a real
domain at localhost behind a trusted CA lets whoever controls it intercept
that site's traffic, so those stay with you in the editors.

The server only answers on `127.0.0.1` and rejects requests from web pages
(Origin and Host checks), so websites can't reach it.

## Passwords

Writing the hosts file needs admin rights. By default every change prompts
(macOS password / Windows UAC). **Settings → Change hosts without password**
instead grants your user account write access to the hosts file once (an ACL
on macOS, `icacls` on Windows), so later toggles, including ones from agents,
don't prompt. The app offers this after the first prompted change.

Trusting the CA happens per user (login keychain on macOS, the user Root store
on Windows) and needs no admin rights.

## Updates

The app checks the latest GitHub release at launch and every six hours. When
there's a newer version it downloads it, checks it against the release's
`SHA256SUMS`, and on macOS also checks that it's signed by the same Apple team
as the running app. Then it offers to restart. An app installed by the `.pkg`
is owned by root, so installing the update asks for your password.
**Settings → Check for updates** checks right away. Development builds don't
update.

## Build and release

```sh
go test ./...                    # unit, integration and JS-parity tests
go build -o hoststray .          # local binary
VERSION=0.11.0 ./scripts/build-release.sh   # everything below, into dist/
VERSION=0.11.0 ./scripts/release.sh         # publish dist/ as a GitHub release
```

`build-release.sh` produces the signed and notarized `Hosts-Tray-<v>-mac.zip`
and `.pkg` (via `scripts/build-mac.sh`), `hoststray-<v>-windows-{amd64,arm64}.exe`
with icon and manifest, and the `SHA256SUMS` the updater requires. Mac signing
uses the Apple credentials in `../.env` (see `../.env.example`); without them
it builds an ad-hoc signed app for local use. `NOTARIZE=0` signs without
notarizing, for quick test builds.

`go test` checks the hosts and `proxy.conf` parsers against the original
JavaScript ones (needs `node`). Two opt-in macOS suites need a person at the
screen:

- `HOSTSTRAY_UI_TESTS=1` clicks real dialogs.
- `HOSTSTRAY_ADMIN_TESTS=1 go test -run Admin ./internal/platform/` runs the
  password prompts (elevated write, password-free on/off, CA trust) against a
  throwaway file and CA. You type your password five times.

## Environment variables

| Variable | Default | Purpose |
| --- | --- | --- |
| `PORT` | `443` | Proxy port |
| `LISTEN_HOST` | all interfaces | Proxy listen address, e.g. `127.0.0.1` |
| `FORWARD_HOST` | `127.0.0.1` | Default target host for routes without one |
| `PROXY_TIMEOUT` | `300` | Upstream response timeout in seconds |
| `HOSTS_PATH` | system hosts file | Work on a copy instead; opens the editor at launch |
| `OPEN_PROXY_EDITOR` | unset | Open the routes editor at launch |
| `HOSTSTRAY_ADMIN_PORT` | `47443` | Port for the editors and MCP |
| `HOSTSTRAY_UPDATE_URL` | GitHub latest release | Release feed, for testing updates |
| `HOSTSTRAY_DATA_DIR` | `~/Library/Application Support/hoststray`, `%AppData%\hoststray` | Data folder |

`--headless` runs without a tray icon (editors, MCP and proxy still work).
Logs go to `hoststray.log` in the data folder.

## Differences from the Electron version

- Websocket upgrades with no matching `ws://`/`wss://` route fall back to the
  web routes, so `* -> :80` also carries your app's own websockets.
- The proxy remembers whether it was on and restarts with the app.
- Linux builds aren't published (the code compiles for it but isn't
  maintained).
