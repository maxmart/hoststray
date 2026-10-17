const { dialog, app } = require('electron')

var httpProxy = require('http-proxy'),
    fs = require('fs'),
    path = require('path'),
    tls = require('tls'),
    https = require('https');
const forge = require('node-forge');
const proxyConfig = require('./proxy-config');



// export all of this as function
module.exports = function() {

    // console.log("Node.js Version:", process.version);   // Node.js version
    // console.log("Environment Variables:", process.env); // All environment variables

    const proxyTimeout = process.env.PROXY_TIMEOUT || 5*60;
    
    // Certs live in userData: a packaged app's cwd is "/" on macOS (read-only),
    // and on Windows the Squirrel app dir changes with every update.
    var homePath = path.join(app.getPath('userData'), "_certs"),
        
        listenPort = process.env.PORT || 443,
        forwardHost = process.env.FORWARD_HOST || '127.0.0.1';

        function generateCertificate(name, CA) {
            const keyPath = path.resolve(homePath, name + ".key");
            const csrPath = path.resolve(homePath, name + ".csr");
            const certPath = path.resolve(homePath, name + ".crt");
        
            // Generate the certificate if missing, or if an old leaf cert would be
            // rejected by macOS (no serverAuth EKU / validity over 825 days).
            if (!fs.existsSync(certPath) || (CA && !leafCertIsUsable(certPath))) {
                console.log("Generating certificate: " + certPath);
        
                // Generate the RSA key pair
                const keys = forge.pki.rsa.generateKeyPair(2048);
                
                // Write the private key to a file
                fs.writeFileSync(keyPath, forge.pki.privateKeyToPem(keys.privateKey));
        
                // Create a CSR (Certificate Signing Request)
                const csr = forge.pki.createCertificationRequest();
                csr.publicKey = keys.publicKey;
                csr.setSubject([{
                    name: 'commonName',
                    value: name,
                }]);
        
                // Sign the CSR with the private key
                csr.sign(keys.privateKey);
        
                // Write the CSR to a file
                fs.writeFileSync(csrPath, forge.pki.certificationRequestToPem(csr));
        
                // If CA is provided, sign the CSR with the CA's certificate and key
                if (CA) {
                    const caCertPem = fs.readFileSync(CA.cert, 'utf8');
                    const caKeyPem = fs.readFileSync(CA.key, 'utf8');
        
                    const caCert = forge.pki.certificateFromPem(caCertPem);
                    const caPrivateKey = forge.pki.privateKeyFromPem(caKeyPem);
        
                    // Create a new certificate signed by the CA
                    const cert = forge.pki.createCertificate();
                    cert.serialNumber = new Date().getTime().toString();
                    cert.validity.notBefore = new Date();
                    cert.validity.notAfter = new Date();
                    cert.validity.notAfter.setDate(cert.validity.notBefore.getDate() + 800); // Apple caps TLS leaf certs at 825 days
        
                    cert.setSubject(csr.subject.attributes);
                    cert.setIssuer(caCert.subject.attributes);
                    cert.publicKey = csr.publicKey;
        
                    // Set extensions from the config file
                    cert.setExtensions([
                        { name: 'basicConstraints', cA: false },
                        { name: 'keyUsage', digitalSignature: true, keyEncipherment: true },
                        { name: 'extKeyUsage', serverAuth: true }, // required by macOS
                        {
                            name: 'subjectAltName',
                            altNames: [{ type: 2, value: name }]  // DNS type for SAN (subjectAltName)
                        }
                    ]);
        
                    // Sign the certificate with the CA's private key
                    cert.sign(caPrivateKey, forge.md.sha256.create());
        
                    // Write the signed certificate to a file
                    fs.writeFileSync(certPath, forge.pki.certificateToPem(cert));
                } else {
                    console.log("Add this cert as a trusted CA Root to get rid of SSL warnings: " + certPath);
        
                    // Self-sign the certificate (for development purposes)
                    const cert = forge.pki.createCertificate();
                    cert.serialNumber = new Date().getTime().toString();
                    cert.validity.notBefore = new Date();
                    cert.validity.notAfter = new Date();
                    cert.validity.notAfter.setDate(cert.validity.notBefore.getDate() + 1001); // Valid for 1001 days
        
                    cert.setSubject(csr.subject.attributes);
                    cert.setIssuer(csr.subject.attributes);  // Self-signing so issuer == subject
                    cert.publicKey = csr.publicKey;
        
                    // Set extensions for self-signed certificates (similar to the OpenSSL config)
                    cert.setExtensions([
                        { name: 'basicConstraints', cA: true },
                        { name: 'keyUsage', digitalSignature: true, keyCertSign: true },
                        {
                            name: 'subjectAltName',
                            altNames: [{ type: 2, value: name }]  // DNS type for SAN
                        }
                    ]);
        
                    // Self-sign the certificate
                    cert.sign(keys.privateKey, forge.md.sha256.create());
        
                    // Write the self-signed certificate to a file
                    fs.writeFileSync(certPath, forge.pki.certificateToPem(cert));

                    const response = dialog.showMessageBoxSync(null, {
                        type: "info",
                        buttons: ['Cancel', 'Proceed', 'I\'ll do it myself'],
                        defaultId: 1,
                        title: 'Administrator Privileges Required',
                        message: 'To install the CA certificate, we need administrator privileges.',
                        detail: 'This is necessary to add the certificate to your system’s trusted root certificate store, ensuring your connection is secure.',
                    });

                    if (response === 1) {
                        addCAToTrustedRoot(certPath);
                    } else if (response === 0) {
                        console.log("User declined :(")
                        dialog.showMessageBoxSync(null, {
                            type: "info",
                            title: 'CA Certificate Installation',
                            message: 'We respect your decision.',
                            detail: 'The application may not function correctly without proper certificate installation. Please reconsider when you have time.'
                        });
                    } else {
                        console.log("User will do it manually")
                        dialog.showMessageBoxSync(null, {
                            type: "info",
                            title: 'CA Certificate Installation',
                            message: 'You can manually install the CA certificate',
                            detail: 'You can manually install the CA certificate by running this command:'
                            + '\n\n' + trustCommand(certPath)
                        });
                    }
                }
            }
        
            return {
                cert: certPath,
                key: keyPath,
            };
        }
        

    if (!fs.existsSync(homePath)) {
        fs.mkdirSync(homePath, { recursive: true });
        // Carry over a CA created by older versions in the cwd so it doesn't
        // have to be trusted again.
        const legacy = path.resolve("_certs");
        if (legacy !== homePath && fs.existsSync(legacy)) {
            for (const f of fs.readdirSync(legacy)) {
                try { fs.copyFileSync(path.join(legacy, f), path.join(homePath, f)); } catch (_) { /* ignore */ }
            }
        }
    }

    // force the CA
    var CA = generateCertificate('ssl.proxy.hoststray.cupmanager.net');

    var ssl = {
        SNICallback: function (domain, callback) {
            var domainCert = generateCertificate(domain, CA),
                ctx = tls.createSecureContext({
                    key: fs.readFileSync(domainCert.key),
                    cert: fs.readFileSync(domainCert.cert),
                    ca: [fs.readFileSync(CA.cert)],
                    ciphers: "AES128+EECDH:AES128+EDH"
                });

            return callback(null, ctx);
        },

        key: fs.readFileSync(CA.key),
        cert: fs.readFileSync(CA.cert)
    };

    // --- Routing driven by proxy.conf ------------------------------------
    const configFile = proxyConfig.ensureConfigFile(app.getPath('userData'), __dirname);
    const routes = proxyConfig.toRuntime(
        proxyConfig.parse(fs.readFileSync(configFile, 'utf8')),
        { forwardHost }
    );
    console.log("Proxy config: " + configFile);

    function makeProxy(route, isWs) {
        const server = httpProxy.createProxyServer({
            target: { host: route.host, port: route.port },
            ws: isWs,
            proxyTimeout: proxyTimeout * 1000,
        });
        server.on('error', function (err, req, res) {
            console.error('Proxy error for ' + (req && req.url) + ':', err && (err.message || err));
            if (res && res.writeHead) {
                res.writeHead(502, { 'Content-Type': 'text/plain' });
                res.end('Proxy error.\n\n' + (err && (err.stack || err.message || String(err))));
            } else if (res && res.destroy) {
                res.destroy(); // websocket: res is the raw socket
            }
        });
        if (!isWs) {
            server.on('proxyReq', function (proxyReq) {
                proxyReq.setHeader('X-Forwarded-Protocol', 'https');
                proxyReq.setHeader('X-Forwarded-Proto', 'https');
                proxyReq.setHeader('X-Forwarded-Port', listenPort);
            });
        }
        return Object.assign({}, route, { server });
    }

    const webRoutes = routes.web.map(function (r) { return makeProxy(r, false); });
    const wsRoutes = routes.ws.map(function (r) { return makeProxy(r, true); });

    // Pick the route whose path prefix best (longest) matches the request URL.
    // An empty prefix ("*") matches everything and acts as the catch-all.
    function pickRoute(list, url) {
        var best = null;
        for (var i = 0; i < list.length; i++) {
            var prefix = list[i].pathPrefix || "";
            if (prefix === "" || url.indexOf(prefix) === 0) {
                if (!best || prefix.length > (best.pathPrefix || "").length) best = list[i];
            }
        }
        return best;
    }

    var server = https.createServer(ssl, function (req, res) {
        console.log(req.method + " https://" + req.headers.host + req.url);
        const route = pickRoute(webRoutes, req.url);
        if (!route) {
            res.writeHead(502, { 'Content-Type': 'text/plain' });
            res.end('No matching web route in proxy.conf for ' + req.url);
            return;
        }
        route.server.web(req, res);
    }).on('upgrade', function (req, socket, head) {
        console.log("Websocket: " + req.method + " https://" + req.headers.host + req.url);
        const route = pickRoute(wsRoutes, req.url);
        if (!route) {
            console.error("No websocket route in proxy.conf for " + req.url);
            socket.destroy();
            return;
        }
        route.server.ws(req, socket, head);
    }).on('error', function (err) {
        console.error('Proxy server error:', err);
        dialog.showMessageBox(null, {
            type: 'error',
            title: 'HTTPS Proxy',
            message: 'The proxy could not listen on port ' + listenPort + '.',
            detail: err.code === 'EADDRINUSE'
                ? 'Another program is already using that port.'
                : (err.message || String(err))
        });
    }).listen(listenPort);

    console.log("Listening on %s with %d web route(s) and %d websocket route(s). Default forward host: %s",
        listenPort, webRoutes.length, wsRoutes.length, forwardHost);

    return server;
};


// Leaf certs from older versions lack the serverAuth EKU and run 1001 days,
// which macOS rejects. Treat those (and expired ones) as needing regeneration.
function leafCertIsUsable(certPath) {
    try {
        const cert = forge.pki.certificateFromPem(fs.readFileSync(certPath, 'utf8'));
        const eku = cert.getExtension('extKeyUsage');
        const days = (cert.validity.notAfter - cert.validity.notBefore) / 86400000;
        return !!(eku && eku.serverAuth) && days <= 825 && cert.validity.notAfter > new Date();
    } catch (_) {
        return false;
    }
}

// Command the user can run themselves to trust the CA.
function trustCommand(caCertPath) {
    if (process.platform === 'win32') return `certutil -addstore Root "${caCertPath}"`;
    return `security add-trusted-cert -r trustRoot -k ~/Library/Keychains/login.keychain-db "${caCertPath}"`;
}

function showTrustResult(error, command) {
    if (error) {
        dialog.showMessageBox(null, {
            type: "error",
            title: 'CA Certificate Installation Failed',
            message: 'The CA certificate could not be installed.',
            detail: 'Please try again or manually install the CA certificate by running this command:\n\n' + command
        });
    } else {
        dialog.showMessageBox(null, {
            type: "info",
            title: 'CA Certificate Installed',
            message: 'The CA certificate has been successfully installed.',
            detail: 'You can now close this window.'
        });
    }
}

function addCAToTrustedRoot(caCertPath) {
    const execOptions = { name: 'Hoststray' };

    const platform = process.platform;

    if (platform === 'darwin') {
        // Trust the CA in the user's login keychain. No sudo needed: macOS shows
        // its own password prompt, and running this as root via osascript is
        // refused on recent macOS ("no user interaction was possible").
        const keychain = path.join(app.getPath('home'), 'Library/Keychains/login.keychain-db');
        require('child_process').execFile('security',
            ['add-trusted-cert', '-r', 'trustRoot', '-k', keychain, caCertPath],
            function (error) {
                console.log({error});
                showTrustResult(error, trustCommand(caCertPath));
            });
        return;
    }

    const command = trustCommand(caCertPath);

    // Run the command with elevated privileges
    var sudo = require('sudo-prompt');
    sudo.exec(command, execOptions, function (error, stdout, stderr) {
        console.log({error});
        showTrustResult(error, command);
    })
}

function getCertificateThumbprintFromFile(certFilePath) {
    const certPem = fs.readFileSync(certFilePath, 'utf8');
    const cert = forge.pki.certificateFromPem(certPem);
    const der = forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes();
    const sha1 = forge.md.sha1.create();
    sha1.update(der);
    return sha1.digest().toHex().toUpperCase();
}
function removeCertificate(certFilePath) {
    const thumbprint = getCertificateThumbprintFromFile(certFilePath);
    const command = `certutil -delstore Root ${thumbprint}`;
    const execOptions = { name: 'Hoststray' };

    sudo.exec(command, execOptions, function (error, stdout, stderr) {
        if (error) {
            dialog.showMessageBox(null, {
                type: "error",
                title: 'CA Certificate Removal Failed',
                message: 'The CA certificate could not be removed.',
                detail: 'Please try again or manually remove the CA certificate by running this command:'
                + (process.platform === 'win32' ? '\n\n' + command : '\n\n' + `sudo ${command}`)
            });
        } else {
            dialog.showMessageBox(null, {
                type: "info",
                title: 'CA Certificate Removed',
                message: 'The CA certificate has been successfully removed.',
                detail: 'You can now close this window.'
            });
        }
    })
}


