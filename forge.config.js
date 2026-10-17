const { FusesPlugin } = require('@electron-forge/plugin-fuses');
const { FuseV1Options, FuseVersion } = require('@electron/fuses');
const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');

// ---------------------------------------------------------------------------
// Code signing is opt-in via environment variables. When the relevant vars are
// absent (e.g. local dev builds), nothing is signed and the build still works.
// See SIGNING.md for how to obtain certificates and which vars to set.
// ---------------------------------------------------------------------------

// --- macOS: Developer ID Application cert (in keychain) + notarization ------
const macSigning = process.env.APPLE_TEAM_ID || process.env.APPLE_API_KEY;
const osxSign = macSigning ? {} : undefined; // {} = sensible @electron/osx-sign defaults

let osxNotarize;
if (process.env.APPLE_API_KEY) {
    // App Store Connect API key (recommended for CI)
    osxNotarize = {
        appleApiKey: process.env.APPLE_API_KEY,
        appleApiKeyId: process.env.APPLE_API_KEY_ID,
        appleApiIssuer: process.env.APPLE_API_ISSUER,
    };
} else if (process.env.APPLE_ID && process.env.APPLE_PASSWORD && process.env.APPLE_TEAM_ID) {
    // App-specific password
    osxNotarize = {
        appleId: process.env.APPLE_ID,
        appleIdPassword: process.env.APPLE_PASSWORD,
        teamId: process.env.APPLE_TEAM_ID,
    };
}

// Files packed into app.asar (besides production node_modules).
const APP_FILES = [
    '/package.json', '/main.js', '/preload.js', '/proxy.js', '/proxy-config.js',
    '/hosts-model.js', '/editor.html', '/proxy-editor.html', '/proxy.conf',
];

// --- macOS: .pkg installer ---------------------------------------------------
// Built in postMake from the signed .app when a "Developer ID Installer" identity
// is configured. Users install from the .pkg; auto-update still uses the zip.
const macInstallerIdentity = process.env.APPLE_INSTALLER_IDENTITY;

function notarytoolAuth() {
    if (process.env.APPLE_API_KEY) {
        return ['--key', process.env.APPLE_API_KEY, '--key-id', process.env.APPLE_API_KEY_ID,
            '--issuer', process.env.APPLE_API_ISSUER];
    }
    return ['--apple-id', process.env.APPLE_ID, '--password', process.env.APPLE_PASSWORD,
        '--team-id', process.env.APPLE_TEAM_ID];
}

function buildMacPkg(appPath, pkgPath) {
    const run = (cmd, args) => execFileSync(cmd, args, { stdio: 'inherit' });
    const work = fs.mkdtempSync(path.join(require('os').tmpdir(), 'hoststray-pkg-'));
    const root = path.join(work, 'root');
    const plist = path.join(work, 'component.plist');
    const componentPkg = path.join(work, 'component.pkg');
    try {
        fs.mkdirSync(root);
        run('ditto', [appPath, path.join(root, path.basename(appPath))]);
        // Not relocatable: otherwise Installer "updates" any other copy of the
        // app it finds on disk (e.g. in out/) instead of installing to /Applications.
        run('pkgbuild', ['--analyze', '--root', root, plist]);
        run('/usr/libexec/PlistBuddy', ['-c', 'Set :0:BundleIsRelocatable false', plist]);
        run('pkgbuild', ['--root', root, '--component-plist', plist,
            '--install-location', '/Applications', componentPkg]);
        run('productbuild', ['--package', componentPkg, '--sign', macInstallerIdentity, pkgPath]);
        if (osxNotarize) {
            run('xcrun', ['notarytool', 'submit', pkgPath, ...notarytoolAuth(), '--wait']);
            run('xcrun', ['stapler', 'staple', pkgPath]);
        }
    } finally {
        fs.rmSync(work, { recursive: true, force: true });
    }
}

// --- Windows: Azure Trusted Signing (preferred) or a hardware-token .pfx -----
// Since June 2023 the private key must live on a FIPS-140 hardware module, so a
// loose .pfx is only viable via a hardware token / HSM path.
let windowsSignParams; // custom signtool params (Azure dlib approach)
if (process.env.AZURE_CODE_SIGNING_DLIB && process.env.AZURE_METADATA_JSON) {
    windowsSignParams = `/v /debug /dlib "${process.env.AZURE_CODE_SIGNING_DLIB}" /dmdf "${process.env.AZURE_METADATA_JSON}"`;
}

const squirrelConfig = {
    name: 'hoststray',
    title: 'Hosts Tray',
    setupIcon: 'loop-circular-64.ico',
    noMsi: true,
    shortcutName: 'Hosts Tray',
    iconUrl: 'https://www.iconsdb.com/icons/download/green/loop-circular-64.ico',
};

if (windowsSignParams) {
    // Sign the generated Setup.exe with the same params used for the binaries.
    squirrelConfig.signWithParams = windowsSignParams;
} else if (process.env.WINDOWS_CERTIFICATE_FILE) {
    squirrelConfig.certificateFile = process.env.WINDOWS_CERTIFICATE_FILE;
    squirrelConfig.certificatePassword = process.env.WINDOWS_CERTIFICATE_PASSWORD;
}

module.exports = {
    packagerConfig: {
        asar: true,
        // Ship only what the app needs. By default the whole project dir is
        // packed, which would include .env and _certs/ (the CA private key).
        ignore: (file) => !(
            file === '' ||
            file === '/node_modules' || file.startsWith('/node_modules/') ||
            APP_FILES.includes(file)
        ),
        // macOS only: a readable bundle name and icon. The Windows exe keeps its
        // name (Squirrel depends on it), and userData stays "hoststray" either way.
        ...(process.platform === 'darwin' ? { name: 'Hosts Tray', icon: 'icon.icns' } : {}),
        // Tray-only app: no Dock icon or app menu on macOS.
        extendInfo: { LSUIElement: true },
        ...(osxSign ? { osxSign } : {}),
        ...(osxNotarize ? { osxNotarize } : {}),
        // Signs the app's .exe/.dll inside the package (before the installer is built).
        ...(windowsSignParams ? { windowsSign: { signWithParams: windowsSignParams } } : {}),
    },
    rebuildConfig: {},
    makers: [
        {
            name: '@electron-forge/maker-squirrel',
            config: squirrelConfig,
        },
        {
            name: '@electron-forge/maker-zip',
            platforms: ['darwin'],
        },
        {
            name: '@electron-forge/maker-deb',
            config: {},
        },
        {
            name: '@electron-forge/maker-rpm',
            config: {},
        },
    ],
    publishers: [
        {
            name: '@electron-forge/publisher-github',
            config: {
                repository: {
                    owner: 'maxmart',
                    name: 'hoststray'
                },
                prerelease: false
            }
        }
    ],
    hooks: {
        postMake: async (forgeConfig, makeResults) => {
            if (!macInstallerIdentity) return makeResults;
            for (const result of makeResults) {
                if (result.platform !== 'darwin') continue;
                const name = forgeConfig.packagerConfig.name || result.packageJSON.productName || result.packageJSON.name;
                const appPath = path.resolve(__dirname, 'out', `${name}-darwin-${result.arch}`, `${name}.app`);
                const pkgPath = path.resolve(__dirname, 'out', 'make',
                    `${name}-darwin-${result.arch}-${result.packageJSON.version}.pkg`);
                buildMacPkg(appPath, pkgPath);
                result.artifacts.push(pkgPath);
            }
            return makeResults;
        },
    },
    plugins: [
        {
            name: '@electron-forge/plugin-auto-unpack-natives',
            config: {},
        },
        // Fuses are used to enable/disable various Electron functionality
        // at package time, before code signing the application
        new FusesPlugin({
            version: FuseVersion.V1,
            [FuseV1Options.RunAsNode]: false,
            [FuseV1Options.EnableCookieEncryption]: true,
            [FuseV1Options.EnableNodeOptionsEnvironmentVariable]: false,
            [FuseV1Options.EnableNodeCliInspectArguments]: false,
            [FuseV1Options.EnableEmbeddedAsarIntegrityValidation]: true,
            [FuseV1Options.OnlyLoadAppFromAsar]: true,
        }),
    ],
};
