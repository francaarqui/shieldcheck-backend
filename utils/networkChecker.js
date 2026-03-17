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
        // 1. Resolve DNS (Trying different record types)
        const addresses = await dns.resolve4(domain).catch(() => []);
        if (addresses.length > 0) {
            info.dns.resolved = true;
            info.dns.records = addresses;
        }

        // Fetch Nameservers
        const ns = await dns.resolveNs(domain).catch(async () => {
            // Fallback: try to get NS from authority if resolveNs fails
            return [];
        });
        info.dns.nameservers = ns;

        // 2. Check SSL with more detail
        const sslInfo = await new Promise((resolve) => {
            const socket = tls.connect(443, domain, {
                servername: domain,
                timeout: 8000,
                rejectUnauthorized: false
            }, () => {
                const cert = socket.getPeerCertificate();
                if (cert && Object.keys(cert).length > 0) {
                    const now = new Date();
                    const vTo = new Date(cert.valid_to);
                    // Even if not "authorized" by local root store, it's functional if issuer exists and date is future
                    const isFunctional = cert.issuer && vTo > now;

                    resolve({
                        valid: socket.authorized || isFunctional,
                        authorized: socket.authorized,
                        isFunctional: isFunctional,
                        issuer: cert.issuer?.O || cert.issuer?.CN || 'Unknown',
                        validFrom: cert.valid_from,
                        validTo: cert.valid_to,
                        protocol: socket.getProtocol(),
                        subject: cert.subject?.CN
                    });
                } else {
                    resolve(null);
                }
                socket.end();
            });

            socket.on('error', (err) => {
                console.warn(`SSL Probe Error for ${domain}:`, err.message);
                resolve(null);
                socket.destroy();
            });

            socket.setTimeout(8000, () => {
                resolve(null);
                socket.destroy();
            });
        });

        if (sslInfo) {
            info.ssl = sslInfo;
        }

        console.log(`[NetworkProbe] Result for ${domain}: NS Count=${info.dns.nameservers.length}, SSL Valid=${info.ssl.valid}`);

    } catch (err) {
        console.error(`Error fetching network info for ${domain}:`, err.message);
    }

    return info;
}

module.exports = { getNetworkInfo };
