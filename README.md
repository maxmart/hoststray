<p align="center">
  <img src="scripts/icon.png" width="96" alt="">
</p>

<h1 align="center">Hosts Tray</h1>

<p align="center">
  <b>Easily switch hosts and SSL proxy from your tray.</b><br>
  Define groups of entries in your hosts file, and run a local HTTPS proxy with self-signed certificates that generate on-the-fly.
</p>

<p align="center">
  <a href="https://github.com/maxmart/hoststray/releases/latest"><img alt="Latest release" src="https://img.shields.io/github/v/release/maxmart/hoststray?color=1f9d55"></a>
  <img alt="macOS and Windows" src="https://img.shields.io/badge/platform-macOS%20%7C%20Windows-555">
  <a href="LICENSE"><img alt="MIT license" src="https://img.shields.io/github/license/maxmart/hoststray?color=555"></a>
</p>

<p align="center">
  <a href="https://github.com/maxmart/hoststray/releases/latest"><b>Download for macOS</b></a> ·
  <a href="https://github.com/maxmart/hoststray/releases/latest"><b>Download for Windows</b></a>
</p>

<p align="center">
  <img src="docs/screenshots/tray.gif" width="320" alt="The Hosts Tray menu: turning on the HTTPS proxy and a hosts group, and the tray icon turning green">
</p>

## Why Hosts Tray

Cookies, CORS, OAuth callbacks and service workers often only behave on the
real hostname over HTTPS. Getting there by hand means editing an admin-owned
hosts file, generating and trusting certificates, running a reverse proxy, and
then waiting for the browser to notice. Hosts Tray does it from a tray icon:
one small native app, about 10 MB to download, no config files to write.

<table>
  <tr>
    <td width="34%">🔀 <b>Hosts and HTTPS in one switch</b></td>
    <td>Tick a group and its names point at your machine. Turn on the proxy and they answer over HTTPS with a trusted certificate, made on the fly for each name. No hosts editor, <code>mkcert</code> and reverse proxy to wire together.</td>
  </tr>
  <tr>
    <td>🔁 <b>Browsers follow the switch</b></td>
    <td>Browsers reuse open connections and can stay on the old server for minutes. Hosts Tray flushes the DNS cache and drops those connections, so the next request reaches the new server within seconds.</td>
  </tr>
  <tr>
    <td>🤖 <b>Coding agents can drive it</b></td>
    <td>A one-click skill for Claude Code and other agents. They switch groups and the proxy, and ask before adding hostnames: nothing changes unless you click <b>Add</b>.</td>
  </tr>
  <tr>
    <td>🔑 <b>No password prompts, safely</b></td>
    <td>An optional helper switches groups without a password, and can do nothing else. See <a href="#security">Security</a>.</td>
  </tr>
</table>

## Quick start

1. **Install** the [latest release](https://github.com/maxmart/hoststray/releases/latest):
   the `.pkg` on macOS, `Hosts-Tray-<version>-windows-amd64-setup.exe` on Windows.
2. **Add a group** in **Open Hosts Tray… → Hosts**, or straight in your hosts file:
   ```
   #==== Shop
   127.0.0.1  shop.example.com
   #====
   ```
3. **Turn on the proxy** from the tray menu and trust the certificate when asked.
   `https://shop.example.com` now reaches `localhost:80`; change the target
   under **Proxy routes**.

## How it works

```mermaid
flowchart LR
    B["Browser<br/>https://shop.example.com"] -- "hosts file:<br/>127.0.0.1" --> P["Hosts Tray :443<br/>certificate from a local CA"]
    P -- "/" --> A["localhost:3000"]
    P -- "/api" --> C["localhost:8080"]
    P -- "wss /socket" --> D["localhost:3001"]
```

The hosts file points the name at your machine, the proxy answers with a
certificate for that name signed by a CA your computer trusts, and the route
table decides which local port gets the request.

## Features

- 🗂️ **Hosts groups.** Sections of your hosts file, switched on and off from the tray menu.
- 🔒 **HTTPS proxy.** A certificate per hostname on the fly, websockets included.
- 🔁 **Browsers follow the switch.** DNS cache flushed and stale connections dropped on every change.
- 🤖 **Agent skill.** Claude Code and other coding agents switch groups and the proxy, and ask before adding hostnames.
- 🧭 **Routes.** Send paths and websocket upgrades to different ports; changes apply on save.
- 🔑 **No password prompts, if you want.** Opt-in settings for switching groups and for editing.
- 🖥️ **Console.** One local web page for the proxy, groups, routes and settings.
- 📦 **Move to another computer.** Export and import groups and routes as one text file.
- 🔄 **Auto-update** from GitHub Releases, checksum-verified.

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/screenshots/overview-dark.png">
    <img src="docs/screenshots/overview-light.png" width="820" alt="The Hosts Tray console: the HTTPS proxy switch and three hosts groups">
  </picture>
</p>

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/screenshots/hosts-dark.png">
    <img src="docs/screenshots/hosts-light.png" width="49%" alt="The hosts editor with three groups">
  </picture>
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/screenshots/routes-dark.png">
    <img src="docs/screenshots/routes-light.png" width="49%" alt="The proxy routes editor">
  </picture>
</p>

## Compared to

| | SwitchHosts | mkcert | Caddy by hand | **Hosts Tray** |
| --- | :---: | :---: | :---: | :---: |
| Toggle hosts groups from a menu | ✅ | | | ✅ |
| Trusted HTTPS certificates | | ✅ one command per name | ✅ `tls internal` | ✅ automatic per name |
| Reverse proxy and websockets | | | ✅ | ✅ |
| Browsers switch right away | | | | ✅ |
| No config file to write | ✅ | ✅ | | ✅ |
| Coding agents can drive it | | | | ✅ |

## Install

Download from the [latest release](https://github.com/maxmart/hoststray/releases/latest):

- **macOS**: `Hosts-Tray-<version>.pkg` installs to Applications. The
  `-mac.zip` contains the same app if you'd rather drag it there yourself.
- **Windows**: `Hosts-Tray-<version>-windows-amd64-setup.exe` (or `arm64`)
  installs for your user into `%LOCALAPPDATA%\Programs\Hosts Tray`, without
  admin rights, with a Start menu entry and an uninstaller. The bare
  `hoststray-<version>-windows-amd64.exe` also runs from anywhere.

The app lives in the menu bar (macOS) or the notification area (Windows);
there's no window or Dock icon.

Uninstalling on Windows asks whether to also remove settings and
certificates; yes also stops Windows trusting the Hosts Tray CA and removes
password-free hosts editing. The password-free helper is always removed
(one UAC prompt, if it's installed). Hosts file entries are always kept.

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
only when all of its entries are. Only IPv4 entries are managed; comments,
blank lines and anything else are preserved byte for byte.

**Open Hosts Tray…** in the tray menu opens the console in your browser;
**Edit hosts…** and **Edit proxy routes…** open it at those sections. It's
served by the app on `127.0.0.1` and only works through the links from the
tray menu.

### Passwords

The hosts file belongs to the system, so changing it needs admin rights. By
default every change asks for your password (macOS) or a UAC confirmation
(Windows). On macOS that's the system's own admin dialog, which asks for the
password (macOS doesn't offer Touch ID for running things as root).

Two settings, in the tray menu's **Settings** and in the console, take the
prompts away. Each asks one last time when you turn it on.

- **Switch groups without password** installs a small helper: a launchd
  daemon on macOS, a service on Windows. Switching groups on or off, from the
  tray, the console or an agent, then goes through it without a prompt. The
  app offers this after the first prompted switch.
- **Edit hosts without password** gives your user account write access to the
  hosts file, so editing it in the console, importing and agent additions
  stop asking as well.

What each one lets other programs do is under [Security](#security).

### Stale connections

Browsers keep connections open and reuse them without looking the name up
again, so after a switch they can stay on the old server for minutes. When the
helper switches a group, or a change goes through the password prompt, the
DNS cache is flushed and connections to where a changed hostname used to point
are dropped, so the next request goes to the new address. On Windows this
covers IPv4 addresses. Edits saved directly, with **Edit hosts without
password**, only drop the proxy's own connections.

## HTTPS proxy

Turn on **HTTPS proxy on :443** in the tray menu. The icon turns green while
the proxy runs, and it stays on across restarts until you turn it off.

On first start the app creates a root CA and offers to trust it for your user
account (macOS asks for your password; Windows asks you to confirm). Each
hostname that connects gets its own certificate signed by that CA, so any name
you point at `127.0.0.1` in the hosts file works immediately.

Another program can listen on `127.0.0.1:443` alongside the proxy and quietly
take its traffic. The app checks for that while the proxy runs and tells you
which program it is when it can tell.

Forwarded requests carry `X-Forwarded-Proto: https`, `X-Forwarded-Port`,
`X-Forwarded-Host` and `X-Forwarded-For`, so your backend can build correct
absolute URLs.

### Routes

Routes live in `proxy.conf` in the app's data folder and are edited in the
console (**Edit proxy routes…** in the tray menu). One rule per line:

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

## Moving to another computer

In the console, **Settings > Export** copies or downloads your hosts groups and
proxy routes as one text file. The rest of the hosts file is machine-specific
and stays behind, and so does the certificate authority: the other computer
makes its own and trusts it once.

```
[hosts]
#==== DEV
127.0.0.1  app.example.com
#====
[routes]
* -> :3000
```

**Settings > Import** takes the file or pasted text and shows what will change
before anything does. Groups merge by name: the same name replaces, new names
are added, and groups not in the file are left alone. Routes, when the file has
them, replace the current ones. The hosts file is written once, so at most one
password prompt. Agents can't import.

## Agents

> [!TIP]
> **Settings → Install agent skill** in the tray menu, then ask Claude Code
> something like *"turn on the Shop hosts group and the proxy"*.

Coding agents drive Hosts Tray over its local HTTP API, guided by a skill
file. The menu item writes it to `~/.claude/skills/hoststray/SKILL.md`. Other
agents can read the same file from `http://127.0.0.1:47443/SKILL.md`. No MCP
or other setup is needed.

The skill tells the agent to read a token from `token` in the data folder and
call these endpoints with it:

| Endpoint | What it does |
| --- | --- |
| `GET /api/status` | Groups with their entries, proxy state, port, CA trust, routes |
| `POST /api/group` `{"name","enabled"}` | Switch an existing group on or off |
| `POST /api/group/entries` `{"group","entries":[{"ip","host"}]}` | Ask to add hostnames to a group (created if needed) |
| `POST /api/proxy/enabled` `{"enabled"}` | Start or stop the proxy |

Adding hostnames shows you a dialog listing them, and nothing changes unless
you click **Add**. Everything else (removing or renaming, routes, import,
trusting the CA) stays with you in the console; see [Security](#security).

## Security

Hosts Tray changes a system file and runs a certificate authority your
computer trusts, so it's built to hand out as little power as possible.
Pointing a real domain at your machine behind a trusted CA would let whoever
did it read that site's traffic, so adding or changing where a name points
always needs you.

### The helper

Switching groups without a password needs something running as admin. The app
itself never does; a separate helper does that one job:

```mermaid
flowchart LR
    T["Tray, console, agent"] --> A["Hosts Tray<br/>(runs as you)"]
    A -- "switch group X on/off" --> H["Helper<br/>(admin)"]
    H --> F["hosts file"]
    A -- "any other change:<br/>password prompt, or directly<br/>with Edit hosts without password" --> F
```

- **It can only switch existing groups on or off.** It understands two
  requests: its version, and "turn group X on or off". It reads the hosts file
  itself and comments or uncomments the lines inside that group. It never takes
  file content or new entries, so it can't point a name somewhere new.
- **Only your user account can reach it.** On macOS it listens on a socket in
  `/var/run` owned by your user and checks the caller's user ID on every
  connection. On Windows it's a named pipe whose permissions admit only your
  account, and connections from other machines are refused.
- **The app checks it's the real helper.** Before sending anything, the app
  verifies that the other end runs as root (macOS) or is the Hosts Tray helper
  service itself (Windows), so another program can't pose as it.
- **It stays small.** A few connections at a time, size-limited requests with
  timeouts, and the hosts file is replaced in one atomic step.
- **It cleans up after itself.** It serves one user and one app. If the app is
  deleted, the helper removes itself; the Windows uninstaller removes it
  straight away. After an app update, the app offers to update the helper and
  uses the password prompt until you do.

The trade-off: any program running as you can switch your existing groups
through the helper, just as it could click the tray menu.

**Edit hosts without password** goes further: it gives your account write
access to the hosts file, so any program running as you can edit it. Leave it
off unless you want no prompts at all.

### Password prompts

Prompts come from the system and name Hosts Tray: the macOS admin dialog with
the Hosts Tray icon, or a Windows UAC prompt for `hoststray.exe` itself. The
app runs as admin only for that one step.

### The local API and console

The API and console only answer on `127.0.0.1` and reject requests from web
pages, so websites can't reach them. The agent token is new on each launch and
only works for the four endpoints above. The console uses a separate token
that never touches disk, so agents can't remove or rename anything, change
routes, import, or trust the CA.

### The certificate authority

The CA is created on your computer, its private key stays in the data folder,
and it's trusted for your user account only. Each hostname gets its own
certificate from it. Uninstalling on Windows with *remove settings* removes
the trust.

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

<details>
<summary><b>Environment variables</b></summary>

| Variable | Default | Purpose |
| --- | --- | --- |
| `PORT` | `443` | Proxy port |
| `LISTEN_HOST` | all interfaces | Proxy listen address, e.g. `127.0.0.1` |
| `FORWARD_HOST` | `127.0.0.1` | Default target host for routes without one |
| `PROXY_TIMEOUT` | `300` | Upstream response timeout in seconds |
| `HOSTS_PATH` | system hosts file | Work on a copy instead; opens the console at launch |
| `OPEN_PROXY_EDITOR` | unset | Open the console at proxy routes at launch |
| `HOSTSTRAY_ADMIN_PORT` | `47443` | Port for the console and API |
| `HOSTSTRAY_DATA_DIR` | see above | Data folder |
| `HOSTSTRAY_UPDATE_URL` | GitHub latest release | Release feed, for testing updates |

`--headless` runs without a tray icon (console, API and proxy still work).

</details>

<details>
<summary><b>Development</b></summary>

Needs Go 1.27 or newer; on macOS, Xcode command line tools (the tray uses cgo).

```sh
go run .                         # run from source
go test ./...                    # unit and integration tests
```

On Windows, run `go generate . ./internal/platform` before building: the first
links in the icon and manifest (without it, dialogs fall back to plain Yes/No
boxes), the second builds the helper service the app carries inside it.

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

</details>

<details>
<summary><b>Releasing</b></summary>

```sh
VERSION=0.11.0 ./scripts/build-release.sh   # build everything into dist/
VERSION=0.11.0 ./scripts/release.sh         # publish dist/ as a GitHub release (gh CLI)
```

`build-release.sh` produces `Hosts-Tray-<v>-mac.zip` and `.pkg` (universal,
signed and notarized, via `scripts/build-mac.sh`),
`hoststray-<v>-windows-{amd64,arm64}.exe` with icon, manifest and the helper service, their
installers `Hosts-Tray-<v>-windows-{amd64,arm64}-setup.exe` (needs
`brew install makensis`; skipped without it, see `scripts/windows/installer.nsi`),
and the `SHA256SUMS` the updater requires.

macOS signing needs, in your keychain, a **Developer ID Application**
certificate (and **Developer ID Installer** for the `.pkg`), plus an
app-specific password for notarization. Copy `.env.example` to `.env` and fill
it in. Without it, `build-mac.sh` builds an ad-hoc signed app for local use;
`NOTARIZE=0` signs without notarizing, for quick test builds.

The Windows executables and installers are not code-signed yet, so
SmartScreen warns on first run.

</details>

## License

[MIT](LICENSE)
