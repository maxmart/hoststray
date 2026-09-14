if (require('electron-squirrel-startup')) return;

const { updateElectronApp } = require('update-electron-app');
updateElectronApp(); // additional configuration options available


const { app, Tray, Menu, nativeImage, BrowserWindow, ipcMain } = require('electron')
const fs = require("fs");
const { join } = require('path');
const os = require('os');

const startProxy = require('./proxy.js');
const { parse, serialize, getGroups } = require('./hosts-model');
const proxyConfig = require('./proxy-config');

const winpath = "c:\\Windows\\System32\\drivers\\etc\\hosts";
const macpath = "/etc/hosts";
// HOSTS_PATH lets you point the app at an alternate file (used for safe testing
// against a copy instead of the real, admin-owned system hosts file).
const path = process.env.HOSTS_PATH || (process.platform == "win32" ? winpath : macpath);
let tray

var currentServer = null;
let editorWin = null;
let proxyWin = null;

const baseIconData = 'data:image/png;base64,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';

function createTrayIcon(proxyRunning) {
    const baseIcon = nativeImage.createFromDataURL(baseIconData);
    const size = baseIcon.getSize();
    const bitmap = baseIcon.toBitmap();

    for (let i = 0; i < bitmap.length; i += 4) {
        const r = bitmap[i], g = bitmap[i + 1], b = bitmap[i + 2], a = bitmap[i + 3];
        if (a < 10) continue;
        if (proxyRunning) {
            // Green tint
            bitmap[i]     = Math.round(r * 0.3);
            bitmap[i + 1] = Math.min(255, Math.round(g * 0.5 + 128));
            bitmap[i + 2] = Math.round(b * 0.3);
        } else {
            // Gray tint
            const gray = Math.round(0.299 * r + 0.587 * g + 0.114 * b);
            bitmap[i]     = gray;
            bitmap[i + 1] = gray;
            bitmap[i + 2] = gray;
        }
    }
    return nativeImage.createFromBitmap(bitmap, { width: size.width, height: size.height });
}

function updateTrayIcon() {
    const icon = createTrayIcon(currentServer != null);
    tray.setImage(icon);
    tray.setToolTip(currentServer ? 'Hosts Tray - Proxy ON' : 'Hosts Tray - Proxy OFF');
}

// Tray apps have no persistent window; without this, closing the editor window
// would fire window-all-closed and quit the whole app.
app.on('window-all-closed', () => { /* keep running in the tray */ });

app.whenReady().then(() => {
    const icon = createTrayIcon(false);
    tray = new Tray(icon)

    tray.on('click', () => {
        tray.popUpContextMenu();
    })

    ipcMain.handle('hosts:load', () => {
        return parse(fs.readFileSync(path, 'utf8'));
    });

    ipcMain.handle('hosts:save', async (_event, doc) => {
        let text;
        try {
            text = serialize(doc);
        } catch (err) {
            return { ok: false, error: 'serialize failed: ' + (err && err.message) };
        }
        const res = await writeHosts(text);
        if (res.ok) buildMenu();
        return res;
    });

    ipcMain.handle('proxy:load', () => {
        const file = proxyConfig.ensureConfigFile(app.getPath('userData'), __dirname);
        return proxyConfig.parse(fs.readFileSync(file, 'utf8'));
    });

    ipcMain.handle('proxy:save', (_event, config) => {
        try {
            const file = proxyConfig.ensureConfigFile(app.getPath('userData'), __dirname);
            fs.writeFileSync(file, proxyConfig.serialize(config), { encoding: 'utf8' });
            return { ok: true, restartNeeded: currentServer != null };
        } catch (err) {
            return { ok: false, error: err && (err.message || String(err)) };
        }
    });

    tray.setToolTip('Hosts Tray - Proxy OFF');

    buildMenu();

    // In test mode, open an editor immediately so it's easy to see without
    // hunting for the tray icon.
    if (process.env.HOSTS_PATH) openEditor();
    if (process.env.OPEN_PROXY_EDITOR) openProxyEditor();
})

function buildMenu() {
    if (!tray) return;

    let groups = [];
    try {
        groups = getGroups(parse(fs.readFileSync(path, 'utf8')));
    } catch (err) {
        console.error('Failed to read hosts file:', err);
    }

    // Win11 native menu separators render as a near-invisible gap, so use a
    // disabled line-item as a clearly visible divider instead.
    // const divider = () => ({ label: "──────────────", type: "normal", enabled: false });
    const divider = () => ({type: 'separator'})

    const template = [
        { label: "v" + app.getVersion(), type: "normal", enabled: false },
        {
            label: "Edit hosts…",
            type: "normal",
            click: () => openEditor()
        },
        {
            label: "Edit proxy routes…",
            type: "normal",
            click: () => openProxyEditor()
        },
        divider(),
        {
            label: "HTTPS Proxy on?",
            type: 'checkbox',
            checked: currentServer != null,
            click: () => {
                if (currentServer) {
                    currentServer.close();
                    currentServer = null;
                } else {
                    currentServer = startProxy();
                }
                updateTrayIcon();
                tray.popUpContextMenu(menu, tray.getBounds());
            }
        },
        {
            label: "Launch at start up?",
            type: 'checkbox',
            checked: app.getLoginItemSettings().openAtLogin,
            click: (mi) => {
                app.setLoginItemSettings({ openAtLogin: mi.checked });
                tray.popUpContextMenu(menu, tray.getBounds());
            }
        },
        divider(),
        ...groups.map(group => ({
            label: group.name,
            type: 'checkbox',
            checked: group.enabled,
            click: (mi) => {
                toggleGroup(group.name, mi.checked);
                tray.popUpContextMenu(menu, tray.getBounds());
            }
        })),
        divider(),
        { label: "Quit", type: "normal", click: () => app.quit() }
    ];

    const menu = Menu.buildFromTemplate(template);
    tray.setContextMenu(menu);
}

function openEditor() {
    if (editorWin && !editorWin.isDestroyed()) {
        editorWin.focus();
        return;
    }
    editorWin = new BrowserWindow({
        width: 860,
        height: 720,
        title: 'Hosts Tray — Editor',
        autoHideMenuBar: true,
        webPreferences: {
            preload: join(__dirname, 'preload.js'),
            contextIsolation: true,
            nodeIntegration: false
        }
    });
    editorWin.setMenuBarVisibility(false);
    editorWin.loadFile(join(__dirname, 'editor.html'));
    editorWin.on('closed', () => { editorWin = null; });
}

function openProxyEditor() {
    if (proxyWin && !proxyWin.isDestroyed()) {
        proxyWin.focus();
        return;
    }
    proxyWin = new BrowserWindow({
        width: 720,
        height: 600,
        title: 'Hosts Tray — Proxy Routes',
        autoHideMenuBar: true,
        webPreferences: {
            preload: join(__dirname, 'preload.js'),
            contextIsolation: true,
            nodeIntegration: false
        }
    });
    proxyWin.setMenuBarVisibility(false);
    proxyWin.loadFile(join(__dirname, 'proxy-editor.html'));
    proxyWin.on('closed', () => { proxyWin = null; });
}

// Write the hosts file, falling back to an elevated copy if the direct write is
// blocked by permissions (the hosts file is admin-owned on Windows/macOS).
function writeHosts(content) {
    return new Promise((resolve) => {
        try {
            fs.writeFileSync(path, content, { encoding: "utf8" });
            resolve({ ok: true, elevated: false });
        } catch (err) {
            if (err && (err.code === "EPERM" || err.code === "EACCES")) {
                elevatedWrite(content).then(resolve);
            } else {
                resolve({ ok: false, error: err && (err.message || String(err)) });
            }
        }
    });
}

function elevatedWrite(content) {
    return new Promise((resolve) => {
        const tmp = join(os.tmpdir(), "hoststray-hosts-" + process.pid + ".tmp");
        try {
            fs.writeFileSync(tmp, content, { encoding: "utf8" });
        } catch (e) {
            resolve({ ok: false, error: "temp write failed: " + e.message });
            return;
        }

        const sudo = require("sudo-prompt");
        const command = process.platform === "win32"
            ? `cmd /c copy /Y "${tmp}" "${path}"`
            : `cp "${tmp}" "${path}"`;

        sudo.exec(command, { name: "Hoststray" }, (error) => {
            try { fs.unlinkSync(tmp); } catch (_) { /* ignore */ }
            if (error) {
                resolve({ ok: false, error: "elevated write failed: " + (error.message || String(error)) });
            } else {
                resolve({ ok: true, elevated: true });
            }
        });
    });
}



function toggleGroup(name, enable) {
    let doc;
    try {
        doc = parse(fs.readFileSync(path, 'utf8'));
    } catch (err) {
        console.error('toggleGroup read failed:', err);
        return;
    }

    const group = doc.nodes.find(n => n.t === 'group' && n.name === name);
    if (!group) return;

    for (const child of group.children) {
        if (child.t === 'entry') {
            child.enabled = enable;
            child.raw = null; // regenerate this line on serialize
        }
    }

    writeHosts(serialize(doc)).then(res => {
        if (res.ok) buildMenu();
        else console.error('toggleGroup write failed:', res.error);
    });
}
