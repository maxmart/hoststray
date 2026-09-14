const { FusesPlugin } = require('@electron-forge/plugin-fuses');
const { FuseV1Options, FuseVersion } = require('@electron/fuses');

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
