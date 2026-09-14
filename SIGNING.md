# Code signing & releases

Hosts Tray ships signed installers and auto-updates from GitHub Releases via
[`update-electron-app`](https://github.com/electron/update-electron-app) →
[`update.electronjs.org`](https://update.electronjs.org). Auto-update only runs
in a **packaged, installed** build (it is skipped in `electron .` dev mode).

Signing is **opt-in**: `forge.config.js` reads credentials from environment
variables, and if they're absent it builds unsigned (fine for local testing).
Copy `.env.example` → `.env` and fill in the parts you need.

> You must build each platform **on that platform** — macOS apps can only be
> signed/notarized on macOS, Windows installers signed on Windows.

---

## macOS

**What you need (you already have the Apple Developer account):**

1. A **Developer ID Application** certificate (Certificates → "+" →
   *Developer ID Application*). Download it and double-click to install into your
   **login keychain** on the Mac you build on. This is the cert for apps
   distributed *outside* the Mac App Store — not the "Mac App Distribution" one.
2. Credentials so the notarizer can talk to Apple — pick one:
   - **App Store Connect API key** (best for CI): create one under Users and
     Access → Integrations → App Store Connect API. Set `APPLE_API_KEY` (path to
     the `.p8`), `APPLE_API_KEY_ID`, `APPLE_API_ISSUER`.
   - **App-specific password**: create one at appleid.apple.com. Set `APPLE_ID`,
     `APPLE_PASSWORD`, `APPLE_TEAM_ID`.

`forge.config.js` enables `osxSign` + `osxNotarize` automatically once those vars
are present. Notarization staples the ticket so Gatekeeper passes on first launch.

```bash
# on a Mac, with .env filled in:
dotenv -- npm run make       # build + sign + notarize locally
dotenv -- npm run publish    # ...and upload to GitHub Releases
```

---

## Windows

### How Windows signing works (the short version)

Windows uses **Authenticode**: you sign the `.exe`/installer with a code-signing
certificate, embedding a signature + your identity + a timestamp. When a user
runs it, SmartScreen checks the signature and the publisher's reputation.

- **Unsigned** → "Windows protected your PC" SmartScreen warning every install.
- **OV (Organization Validation)** cert → trusted once it builds reputation.
- **EV (Extended Validation)** cert → instant SmartScreen reputation, but pricier.

**The catch (since June 2023):** the private key for a publicly-trusted code
signing cert must live on a **FIPS-140 hardware module** — you can no longer just
have a `.pfx` file for a new public cert. Practical options:

1. **Azure Trusted Signing** (recommended) — Microsoft's cloud signing service,
   cheap (~$10/mo), no physical token. `signtool` calls a "dlib" that signs in
   the cloud. Requires a US/Canada org (3+ yrs) or eligible individual developer.
2. **Hardware token** — a USB token from DigiCert/Sectigo/etc. You install its
   driver and reference the token; works but awkward for CI.

### Azure Trusted Signing setup

1. Create a Trusted Signing account + certificate profile in the Azure portal.
2. Install the Trusted Signing client (provides `Azure.CodeSigning.Dlib.dll`).
3. Create a `metadata.json` with your endpoint / account / certificate-profile.
4. In `.env` set `AZURE_CODE_SIGNING_DLIB` (path to the dll),
   `AZURE_METADATA_JSON` (path to the json), and the `AZURE_TENANT_ID` /
   `AZURE_CLIENT_ID` / `AZURE_CLIENT_SECRET` service-principal creds (or run
   `az login`). `forge.config.js` then signs both the app binaries and `Setup.exe`.

```powershell
# on Windows, with .env filled in:
dotenv -- npm run make       # build + sign locally
dotenv -- npm run publish    # ...and upload to GitHub Releases
```

### Legacy .pfx / hardware token

If you instead have a `.pfx` on a hardware-backed path, set
`WINDOWS_CERTIFICATE_FILE` + `WINDOWS_CERTIFICATE_PASSWORD` and skip the Azure
vars. (Used only if the Azure vars are unset.)

---

## Publishing a release

1. Bump `version` in `package.json` (the updater compares `app.getVersion()`).
2. `dotenv -- npm run publish` on **each** target OS — Forge builds, signs, and
   uploads the platform assets to a GitHub Release (`GITHUB_TOKEN` required).
3. Installed clients pick up the new version within ~10 min and prompt to restart.

Linux (`.deb`/`.rpm`) has no auto-update — users update via their package manager.
