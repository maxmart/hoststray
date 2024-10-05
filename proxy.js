const { dialog } = require('electron')

var httpProxy = require('http-proxy'),
    execSync = require('child_process').execSync,
    format = require("util").format,
    fs = require('fs'),
    path = require('path'),
    tls = require('tls'),
    https = require('https'),
    sys = require('sys');
const forge = require('node-forge');



// export all of this as function
module.exports = function() {

    // console.log("Node.js Version:", process.version);   // Node.js version
    // console.log("Environment Variables:", process.env); // All environment variables

    const proxyTimeout = process.env.PROXY_TIMEOUT || 5*60;
    
    var homePath = path.resolve("_certs"),
        
        listenPort = process.env.PORT || 443,
        forwardHost = process.env.FORWARD_HOST || 'localhost',
        forwardPort = process.env.FORWARD_PORT || 80;

        function generateCertificate(name, CA) {
            const keyPath = path.resolve(homePath, name + ".key");
            const csrPath = path.resolve(homePath, name + ".csr");
            const certPath = path.resolve(homePath, name + ".crt");
        
            // If the certificate doesn't already exist, generate it
            if (!fs.existsSync(certPath)) {
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
                    cert.validity.notAfter.setDate(cert.validity.notBefore.getDate() + 1001); // Valid for 1001 days
        
                    cert.setSubject(csr.subject.attributes);
                    cert.setIssuer(caCert.subject.attributes);
                    cert.publicKey = csr.publicKey;
        
                    // Set extensions from the config file
                    cert.setExtensions([
                        { name: 'basicConstraints', cA: false },
                        { name: 'keyUsage', digitalSignature: true, keyCertSign: true },
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

                    dialog.showMessageBoxSync(null, {
                        type: "info",
                        buttons: ['Cancel', 'Proceed', 'I\'ll do it myself'],
                        defaultId: 1,
                        title: 'Administrator Privileges Required',
                        message: 'To install the CA certificate, we need administrator privileges.',
                        detail: 'This is necessary to add the certificate to your system’s trusted root certificate store, ensuring your connection is secure.',
                    }).then(({response}) => {
                        if (response === 1) {
                            addCAToTrustedRoot(certPath);
                        } else {
                            console.log("User declined :(")
                            dialog.showMessageBox(null, {
                                type: "info",
                                title: 'CA Certificate Installation',
                                message: 'You can manually install the CA certificate',
                                detail: 'You can manually install the CA certificate by running this command:'
                                + (process.platform === 'win32' ? '\n\n' + `certutil -addstore Root "${certPath}"` : '\n\n' + `sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "${certPath}"`)

                            });
                        }
                    })
                }
            }
        
            return {
                cert: certPath,
                key: keyPath,
            };
        }
        

    fs.existsSync(homePath) || fs.mkdirSync(homePath);

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

    var proxy = httpProxy.createProxyServer({target: {host: forwardHost, port: forwardPort}});

    proxy.on('error', function (err, req, res) {
        res.writeHead && res.writeHead(500, {
            'Content-Type': 'text/plain'
        });

        res.end('Something went wrong.');
    });

    proxy.on('proxyReq', function (proxyReq, req, res, options) {
        proxyReq.setHeader('X-Forwarded-Protocol', 'https');
        proxyReq.setHeader('X-Forwarded-Proto', 'https');
        proxyReq.setHeader('X-Forwarded-Port', listenPort);
    });

    const cmwebWsProxy = httpProxy.createProxyServer({
        target: {
            host: forwardHost,
            port: 5124
        },
        proxyTimeout: proxyTimeout*1000
    });
    cmwebWsProxy.addListener("error", function() {
        console.log("error in cmwebWsProxy: ", arguments);
    })
    const resultsapiWsProxy = httpProxy.createProxyServer({
        target: {
            host: forwardHost,
            port: 5125
        },
        proxyTimeout: proxyTimeout*1000
    });
    resultsapiWsProxy.addListener("error", function() {
        console.log("error in resultsapiWsProxy: ", arguments);
    })

    var server = https.createServer(ssl, function (req, res) {
        console.log(req.method + " https://" + req.headers.host + req.url);
        proxy.web(req, res);
    }).on('upgrade', function (req, socket, head) {
        // proxy.ws(req, socket, head);
        console.log("Websocket: " + req.method + " https://" + req.headers.host + req.url);
        if (req.url.indexOf("/cmweb") == 0) {
            cmwebWsProxy.ws(req, socket, head);
        } else if (req.url.indexOf("/resultsapi") == 0) {
            resultsapiWsProxy.ws(req, socket, head);
        } else {
            console.error("No websocket handling available. Expected /cmweb or /resultsapi")
        }
    }).listen(listenPort);

    // server.close();

    console.log("Listening on %s. Forwarding to http://%s:%d  (and websockets)", listenPort, forwardHost, forwardPort);

    return server;
};


function addCAToTrustedRoot(caCertPath) {
    const execOptions = { name: 'Hoststray' };

    const platform = process.platform;
    let command = '';

    if (platform === 'win32') {
        // Windows command for adding a CA cert
        command = `certutil -addstore Root "${caCertPath}"`;
    } else if (platform === 'darwin') {
        // macOS command for adding a CA cert
        command = `security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "${caCertPath}"`;
    }

    // Run the command with elevated privileges
    var sudo = require('sudo-prompt');
    sudo.exec(command, execOptions, function (error, stdout, stderr) {
        console.log({error});
        if (error) {
            dialog.showMessageBox(null, {
                type: "error",
                title: 'CA Certificate Installation Failed',
                message: 'The CA certificate could not be installed.',
                detail: 'Please try again or manually install the CA certificate by running this command:'
                + (platform === 'win32' ? '\n\n' + command : '\n\n' + `sudo ${command}`)
            });
        } else {
            dialog.showMessageBox(null, {
                type: "info",
                title: 'CA Certificate Installed',
                message: 'The CA certificate has been successfully installed.',
                detail: 'You can now close this window.'
            });
        }
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


