const { dialog } = require('electron')

var httpProxy = require('http-proxy'),
    execSync = require('child_process').execSync,
    format = require("util").format,
    fs = require('fs'),
    path = require('path'),
    tls = require('tls'),
    https = require('https'),
    sys = require('sys');

// export all of this as function
module.exports = function() {

    console.log("Node.js Version:", process.version);   // Node.js version
    console.log("Environment Variables:", process.env); // All environment variables



    var version = require('./package.json').version.split('.')[0];

    if (!execSync) {
        console.log("execSync() is missing. Are you running node v0.12?");
        process.exit(1);
    }


    const proxyTimeout = process.env.PROXY_TIMEOUT || 5*60;
    
    var homePath = path.resolve(process.env.HOME || process.env.HOMEPATH, '.nassau-proxy/v' + version),
        configPath = path.resolve(homePath, 'openssl.conf'),
        listenPort = process.env.PORT || 443,
        forwardHost = process.env.FORWARD_HOST || 'localhost',
        forwardPort = process.env.FORWARD_PORT || 80;

    function generateCertificate(name, CA) {
        var keyPath = path.resolve(homePath, name + ".key"),
            csrPath = path.resolve(homePath, name + ".csr"),
            certPath = path.resolve(homePath, name + ".crt"),
            execOptions = {stdio: [0, null, null], env: {"ALTNAME": "DNS:" + name}},
            command = format(
                '"C:\\Program Files\\Git\\mingw64\\bin\\openssl" req -newkey rsa:2048 -sha256 -nodes -keyout "%s" -out "%s" -subj "/CN=%s" -config "%s" ',
                keyPath, csrPath, name, configPath
            );

        if (false === fs.existsSync(certPath)) {

            if (CA) {
                console.log("Generating certificate: " + certPath);

                // signing key and request:
                execSync(command, execOptions);

                command = format(
                    '"C:\\Program Files\\Git\\mingw64\\bin\\openssl" x509 -req -days 1001 -sha256 -in "%s" -out "%s" -CA "%s" -CAkey "%s" -CAcreateserial -extfile "%s"',
                    csrPath, certPath, CA.cert, CA.key, configPath
                );
            } else {
                console.log("Add this cert as a trusted CA Root to get rid of SSL warnings: " + certPath);

                command = (command + " -x509 -days 1001").replace(csrPath, certPath);
            }

            execSync(command, execOptions);
        }

        return {
            "cert": certPath,
            "key": keyPath
        }
    }

    fs.existsSync(homePath) || fs.mkdirSync(homePath);

    if (false === fs.existsSync(configPath)) {
        fs.writeFileSync(configPath, [
            'extensions = v3_req',

            '[req]',
            'req_extensions = v3_req',
            'distinguished_name = req_distinguished_name',

            '[v3_req]',
            'subjectAltName=$ENV::ALTNAME',

            '[req_distinguished_name]',
            'C = PL',
            'ST = mazowieckie',
            'L = Warsaw',
            'O  = Nassau SC'
        ].join("\n"));
    }

    // force the CA
    var CA = generateCertificate('ssl.proxy.nassau.narzekasz.pl');

    if (process.env.POSTINSTALL) {
        if ("darwin" === process.platform) {
            console.log(format("Adding %s as a trusted certificate to system keychain. \n"
                + "Please provide your root password when asked or skip this step:", CA.cert));
            execSync(format('sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "%s"', CA.cert));
        }
        process.exit();
    }

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