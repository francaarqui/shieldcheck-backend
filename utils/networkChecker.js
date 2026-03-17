const dns = require('dns').promises;
const https = require('https');
const tls = require('tls');

/**
 * Utility to fetch real network data for a domain to avoid AI hallucinations.
 */
async function getNetworkInfo(domain) {
    const info = {
        dns: {
            resolved: false,
            records: [],
            nameservers: []
        },
        ssl: {
            valid: false,
            issuer: null,
            validFrom: null,
            validTo: null,
            protocol: null
        }
    };

    try {
        // 1. Resolve DNS
        const addresses = await dns.resolve4(domain).catch(() => []);
        if (addresses.length > 0) {
            info.dns.resolved = true;
            info.dns.records = addresses;
        }

        const ns = await dns.resolveNs(domain).catch(() => []);
        info.dns.nameservers = ns;

        // 2. Check SSL
        const sslInfo = await new Promise((resolve) => {
            const socket = tls.connect(443, domain, { servername: domain, timeout: 5000 }, () => {
                const cert = socket.getPeerCertificate();
                if (cert && Object.keys(cert).length > 0) {
                    resolve({
                        valid: !socket.authorized ? false : true,
                        issuer: cert.issuer.O,
                        validFrom: cert.valid_from,
                        validTo: cert.valid_to,
                        protocol: socket.getProtocol()
                    });
                } else {
                    resolve(null);
                }
                socket.end();
            });

            socket.on('error', () => {
                resolve(null);
                socket.destroy();
            });

            socket.setTimeout(5000, () => {
                resolve(null);
                socket.destroy();
            });
        });

        if (sslInfo) {
            info.ssl = sslInfo;
        }

    } catch (err) {
        console.error(`Error fetching network info for ${domain}:`, err.message);
    }

    return info;
}

module.exports = { getNetworkInfo };
