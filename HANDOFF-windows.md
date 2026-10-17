# Handoff: finish the Windows version

For a Claude Code session on Max's Windows machine. Read `README.md` first for
what the app does.

## Where things stand

Hosts Tray was rewritten from Electron to Go (branch `go-rewrite`). The macOS
version is **done and tested**: unit and integration tests, the real tray menu,
a browser console, agent access, password prompts, CA trust,
auto-update (including refusing badly signed updates), the signed and
notarized `.pkg` installer.

The Windows code **compiles and passes `go vet`, but has never run on
Windows.** Your job is to run it, test every Windows path below, and fix what
breaks. Linux was removed on purpose; don't add it back.

Keep changes Windows-focused. If a fix needs to touch shared code
(`internal/app`, `internal/proxy`, `internal/hosts`, …), keep it minimal and
run `go test ./...`. The macOS side can't be re-tested from Windows. Ask Max
before long side quests (VMs, new tooling, big refactors).

## Setup

```powershell
winget install GoLang.Go     # needs Go 1.27+ (see go.mod)
go test ./...
go build -ldflags "-H windowsgui" -o hoststray.exe .
```

For the release-style exe with icon and manifest, see the Windows part of
`scripts/build-release.sh` (it uses `go run github.com/tc-hib/go-winres`). That
script is bash and meant for the Mac, so run the equivalent commands by hand.

To try things safely, work on a copy of the hosts file and a separate data
folder:

```powershell
$env:HOSTS_PATH = "$env:TEMP\hosts-test"; copy C:\Windows\System32\drivers\etc\hosts $env:HOSTS_PATH
$env:HOSTSTRAY_DATA_DIR = "$env:TEMP\hoststray-test"
$env:PORT = "8443"; $env:HOSTSTRAY_ADMIN_PORT = "47999"
.\hoststray.exe          # or --headless (no tray; console, API, proxy still work)
```

A copy in `%TEMP%` is writable, so it **won't** exercise UAC. To test
elevation, use the real hosts file, or a copy you've made admin-only.

Logs: `hoststray.log` in the data folder.

## Windows-specific code (never run yet)

| File | What it does | Look out for |
| --- | --- | --- |
| `internal/platform/platform_windows.go` | Elevated hosts write: PowerShell `Start-Process -Verb RunAs` running `cmd /c copy`, then `ipconfig /flushdns` | Quoting of paths with spaces; mapping a declined UAC prompt to `ErrCancelled` (exit 1223); hidden console windows |
| same | Password-free mode: `icacls <hosts> /grant "DOMAIN\user:(M)"` and `/remove:g` | Username format from `user.Current()`; whether `Writable()` (open for write, no truncate) detects the grant |
| same | CA trust: `certutil -user -addstore Root` (Windows shows a confirmation) | Whether `CA.Trusted()` (Go `x509` verify against system roots) sees the **user** Root store afterwards |
| same | Dialogs: `MessageBoxW` with Yes/No/Cancel; button names spelled out in the text | Only two real choices on Windows; Cancel or close returns -1 |
| same | Launch at login: `HKCU\...\Run` value "Hosts Tray" | |
| same | Open URL (`ShellExecute`), clipboard (`clip`) | |
| `internal/update/install_windows.go` | Update: rename running exe to `.old`, copy new exe in, start it with `HOSTSTRAY_RESTART=1` (it waits for the old one's port), quit; `.old` removed at next start | Exe in a non-writable folder (e.g. Program Files) fails; Defender holding the new file |
| `icon.go` | Tray icon PNG wrapped as ICO | Does it render, gray when off, green when on? |
| `tray.go` (shared) | fyne systray menu, rebuilt every 2 s when state changes | Left vs right click; flicker on rebuild |

Other things to watch:
- **Windows Defender** sometimes flags programs that edit the hosts file
  (`SettingsModifier:Win32/HostsFileHijack`). Note it if it happens.
- **Port 443**: listening on all interfaces may trigger a Windows Firewall
  prompt; something else (IIS, Skype, VPN clients) may already use 443.
- **Data folder** is `%AppData%\hoststray`. Max may have data there from the
  old Electron version (`proxy.conf`, `_certs\`, the CA). It should be picked
  up as-is.

## Test checklist

1. `go test ./...` passes. `internal/platform` has Windows tests for the
   registry login item and file writability.
2. The app starts with a tray icon. The menu shows version, console links, proxy,
   groups, Settings, Quit.
3. Toggle a group on the **real** hosts file: UAC prompt → file changes → the
   app offers "Change hosts without password?" → Yes (UAC again) → the next
   toggle has no prompt. Then Settings → turn it off → toggling prompts again.
   Decline a UAC prompt: nothing should change, and no error dialog.
4. Turn the proxy on: it offers to trust the certificate → Windows
   confirmation → `https://<a hosts-mapped name>` loads in Edge or Chrome
   without a warning. The tray icon turns green. Check a websocket route if
   you can.
5. **Open Hosts Tray…**, **Edit hosts…** and **Edit proxy routes…** open the console; saving
   works; route changes apply without restarting the proxy.
6. Settings → **Launch at login**, sign out and back in, and it starts.
7. Agents: Settings → **Install agent skill**, then have Claude read the hosts
   status and switch a group (MCP was removed in favour of the skill + API).
8. Auto-update against a local feed (below): old exe → dialog → Restart now →
   new version runs (`/health` shows the new version) and `.old` is cleaned up
   on the next start.
9. Quit from the menu: the process exits and the proxy port is freed.

### Testing auto-update locally

Build two versions with `-ldflags "-H windowsgui -X main.version=0.11.0"`
(and `0.11.1`). Serve a folder over HTTP containing:

- `latest`: `{"tag_name":"v0.11.1","assets":[{"name":"hoststray-0.11.1-windows-amd64.exe","browser_download_url":"http://127.0.0.1:18900/hoststray-0.11.1-windows-amd64.exe"},{"name":"SHA256SUMS","browser_download_url":"http://127.0.0.1:18900/SHA256SUMS"}]}`
- the new exe, named exactly as in `latest`
- `SHA256SUMS`: `<sha256 hex>  hoststray-0.11.1-windows-amd64.exe` (get the hash with `Get-FileHash`)

Then run the 0.11.0 exe with `HOSTSTRAY_UPDATE_URL=http://127.0.0.1:18900/latest`.
Any static file server works; there's no Python on a stock Windows machine,
so a ten-line Go `http.FileServer` is easiest.

## When done

Commit fixes to `go-rewrite` with clear messages, and list for Max what was
tested, what failed and was fixed, and anything still open. Release builds
(`scripts/build-release.sh`) run on the Mac, which also produces the Windows
exes. The Windows exes aren't code-signed yet; that's a separate decision.
