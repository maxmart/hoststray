# Hosts Tray

A small tray app for developers who point real domain names at local services.
It toggles groups of entries in your hosts file and runs a local HTTPS proxy
with auto-generated certificates, so `https://app.example.com` can hit your
dev server on `localhost:3000` without browser warnings.

Windows and macOS. Built with Electron.

## Why

Testing cookies, CORS, OAuth callbacks, or service workers usually needs the
real hostname over HTTPS. SwitchHosts is great but does not have HTTPS proxy builtin. 

Doing that by hand means editing an admin-owned hosts file, generating certs, and running a reverse proxy. 
Hosts Tray wraps all three in a tray icon.

Also supports websockets.

## Features

- **Hosts groups.** Mark sections of your hosts file with `#==== Name` and
  toggle each group on or off from the tray menu.
- **Hosts editor.** Edit entries in a window instead of a text editor. Writes
  fall back to an elevated copy when the file is admin-owned.
- **HTTPS proxy.** Listens on port 443, issues a certificate per hostname on the
  fly from a local CA, and forwards to whatever you configure.
- **Route config.** Send web traffic and websocket upgrades to different ports
  by path prefix, editable from the tray.
- **Trusted CA.** Offers to install the generated root CA into the system
  trust store, or shows you the command to run yourself.
- **Auto-update.** Packaged builds update themselves from GitHub Releases.

## Install

Download the installer for your platform from the
[latest release](https://github.com/maxmart/hoststray/releases/latest).

Or run from source:

```sh
git clone https://github.com/maxmart/hoststray.git
cd hoststray
npm install
npm start
```

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

## HTTPS proxy

Turn on **HTTPS Proxy on?** in the tray menu. The icon turns green while the
proxy is running.

On first start the app creates a root CA under `_certs/` and asks for
permission to add it to the system trust store. Each hostname that connects
gets its own certificate signed by that CA, so any name you point at
`127.0.0.1` in the hosts file works immediately.

Forwarded requests carry `X-Forwarded-Proto: https` and `X-Forwarded-Port`
so your backend can build correct absolute URLs.

### Routes

Routes live in `proxy.conf` in the app's user-data folder and are edited from
**Edit proxy routes…** in the tray menu. One rule per line:

```
# <pattern> -> <target>
* -> :80                       # all HTTPS traffic to 127.0.0.1:80
wss://*/socket -> :5124        # websocket upgrades under /socket to :5124
https://*/api -> 10.0.0.5:8080 # a path prefix to another host
```

- A target of `:PORT` means `127.0.0.1:PORT`. `host:PORT` picks a specific host.
- Patterns starting with `ws://` or `wss://` match websocket upgrades only.
- When several routes match, the longest path prefix wins. `*` is the catch-all.

### Environment variables

| Variable | Default | Purpose |
| --- | --- | --- |
| `PORT` | `443` | Port the proxy listens on |
| `FORWARD_HOST` | `127.0.0.1` | Overrides the default target host for routes without an explicit one |
| `PROXY_TIMEOUT` | `300` | Upstream timeout in seconds |
| `HOSTS_PATH` | system hosts file | Point the app at a different file, useful for testing |
| `OPEN_PROXY_EDITOR` | unset | Open the routes editor on launch |

## Development

```sh
npm start            # run with Electron
npm run package      # build an unpackaged app into out/
npm run make         # build installers for the current platform
```

To try the hosts editor without touching the real hosts file, copy it
somewhere and run with `HOSTS_PATH` pointing at the copy. The editor opens
automatically in that mode.

Releases are built and signed per platform. See [SIGNING.md](SIGNING.md) for
certificates, notarization, and publishing to GitHub Releases.


## License

[MIT](LICENSE)
