// url_validator.js
const readline = require('readline');
const dns = require('dns');
const http = require('http');
const https = require('https');
const url = require('url');

const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

function ask(question) {
    return new Promise(resolve => rl.question(question, resolve));
}

class URLValidator {
    constructor(checkDNS = false, checkHTTP = false, timeout = 5) {
        this.checkDNS = checkDNS;
        this.checkHTTP = checkHTTP;
        this.timeout = timeout;
        this.stats = { total: 0, valid: 0, invalid: 0 };
        this.allowedSchemes = new Set(['http', 'https', 'ftp', 'ftps', 'ws', 'wss', 'mailto', 'tel', 'ssh']);
        this.dangerousSchemes = new Set(['javascript', 'data', 'file', 'vbscript']);
        this.MAX_URL_LENGTH = 2048;
        this.hostnameRegex = /^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63}(?<!-))*\.?[A-Za-z]{2,63}$/;
        this.ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
        this.ipv6Regex = /^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(([0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4})?::([0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4})$/;
    }

    validateScheme(scheme) {
        if (!scheme) return { valid: false, reason: "Missing scheme" };
        const lower = scheme.toLowerCase();
        if (this.dangerousSchemes.has(lower)) {
            return { valid: false, reason: `Dangerous scheme blocked: ${scheme}` };
        }
        if (!this.allowedSchemes.has(lower)) {
            return { valid: false, reason: `Unsupported scheme: ${scheme}` };
        }
        return { valid: true, reason: "OK" };
    }

    validateHost(host) {
        if (!host) return { valid: false, reason: "Missing host" };
        if (host.length > 253) return { valid: false, reason: "Host too long (>253)" };
        // IPv6
        if (host.includes(':')) {
            if (this.ipv6Regex.test(host)) {
                return { valid: true, reason: "OK (IPv6)" };
            }
            return { valid: false, reason: "Invalid IPv6 address" };
        }
        // IPv4
        if (this.ipv4Regex.test(host)) {
            return { valid: true, reason: "OK (IPv4)" };
        }
        // Domain
        if (this.hostnameRegex.test(host)) {
            const parts = host.split('.');
            if (parts.length > 1) {
                const tld = parts[parts.length - 1];
                if (tld.length < 2 || tld.length > 63) {
                    return { valid: false, reason: `Invalid TLD length: ${tld.length}` };
                }
            }
            return { valid: true, reason: "OK (domain)" };
        }
        return { valid: false, reason: "Invalid host format" };
    }

    validatePort(portStr) {
        if (!portStr) return { valid: true, reason: "OK (default port)" };
        const port = parseInt(portStr, 10);
        if (isNaN(port) || port < 1 || port > 65535) {
            return { valid: false, reason: `Invalid port: ${portStr}` };
        }
        return { valid: true, reason: `OK (port ${port})` };
    }

    validatePath(path) {
        if (!path) return { valid: true, reason: "OK (empty path)" };
        for (const ch of path) {
            if (ch.charCodeAt(0) < 32 || '"<>|\\^`{}'.includes(ch)) {
                return { valid: false, reason: `Illegal character in path: ${ch}` };
            }
        }
        // Percent-encoding check
        for (let i = 0; i < path.length; i++) {
            if (path[i] === '%') {
                if (i + 2 >= path.length) {
                    return { valid: false, reason: "Incomplete percent-encoding" };
                }
                const hex = path.substring(i+1, i+3);
                if (!/^[0-9a-fA-F]{2}$/.test(hex)) {
                    return { valid: false, reason: "Invalid percent-encoding" };
                }
            }
        }
        return { valid: true, reason: "OK" };
    }

    validateQuery(query) {
        if (!query) return { valid: true, reason: "OK (empty query)" };
        for (const ch of query) {
            if (ch.charCodeAt(0) < 32) {
                return { valid: false, reason: `Illegal character in query: ${ch}` };
            }
        }
        for (let i = 0; i < query.length; i++) {
            if (query[i] === '%') {
                if (i + 2 >= query.length) {
                    return { valid: false, reason: "Incomplete percent-encoding in query" };
                }
                const hex = query.substring(i+1, i+3);
                if (!/^[0-9a-fA-F]{2}$/.test(hex)) {
                    return { valid: false, reason: "Invalid percent-encoding in query" };
                }
            }
        }
        return { valid: true, reason: "OK" };
    }

    validateFragment(fragment) {
        if (!fragment) return { valid: true, reason: "OK (empty fragment)" };
        for (const ch of fragment) {
            if (ch.charCodeAt(0) < 32 || '"<>|\\^`{}'.includes(ch)) {
                return { valid: false, reason: `Illegal character in fragment: ${ch}` };
            }
        }
        return { valid: true, reason: "OK" };
    }

    checkDNS(host) {
        return new Promise((resolve) => {
            if (!this.checkDNS) { resolve(true); return; }
            dns.lookup(host, (err) => {
                resolve(!err);
            });
        });
    }

    checkHTTPAvailability(rawURL) {
        return new Promise((resolve) => {
            if (!this.checkHTTP) { resolve(true); return; }
            if (!rawURL.startsWith('http://') && !rawURL.startsWith('https://')) {
                resolve(true);
                return;
            }
            const parsed = url.parse(rawURL);
            const options = {
                method: 'HEAD',
                hostname: parsed.hostname,
                port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
                path: parsed.path || '/',
                timeout: this.timeout * 1000
            };
            const req = (parsed.protocol === 'https:' ? https : http).request(options, (res) => {
                resolve(res.statusCode < 400);
            });
            req.on('error', () => resolve(false));
            req.end();
        });
    }

    normalize(rawURL) {
        const parsed = url.parse(rawURL);
        // Lowercase scheme and host
        if (parsed.protocol) parsed.protocol = parsed.protocol.toLowerCase();
        if (parsed.hostname) parsed.hostname = parsed.hostname.toLowerCase();
        // Rebuild
        let result = parsed.protocol + '//' + parsed.hostname;
        if (parsed.port) result += ':' + parsed.port;
        result += parsed.path || '/';
        if (parsed.search) result += parsed.search;
        if (parsed.hash) result += parsed.hash;
        return result;
    }

    async validate(rawURL) {
        this.stats.total++;
        if (rawURL.length > this.MAX_URL_LENGTH) {
            this.stats.invalid++;
            return { valid: false, reason: `URL too long (${rawURL.length} > ${this.MAX_URL_LENGTH})`, normalized: null };
        }
        let parsed;
        try {
            parsed = url.parse(rawURL);
        } catch (e) {
            this.stats.invalid++;
            return { valid: false, reason: `Parse error: ${e.message}`, normalized: null };
        }
        // Scheme
        const schemeResult = this.validateScheme(parsed.protocol ? parsed.protocol.slice(0, -1) : '');
        if (!schemeResult.valid) {
            this.stats.invalid++;
            return { valid: false, reason: `Scheme error: ${schemeResult.reason}`, normalized: null };
        }
        // Host
        if (!parsed.hostname) {
            this.stats.invalid++;
            return { valid: false, reason: "Missing host", normalized: null };
        }
        const hostResult = this.validateHost(parsed.hostname);
        if (!hostResult.valid) {
            this.stats.invalid++;
            return { valid: false, reason: `Host error: ${hostResult.reason}`, normalized: null };
        }
        // Port
        const portResult = this.validatePort(parsed.port);
        if (!portResult.valid) {
            this.stats.invalid++;
            return { valid: false, reason: `Port error: ${portResult.reason}`, normalized: null };
        }
        // Path
        const pathResult = this.validatePath(parsed.path || '');
        if (!pathResult.valid) {
            this.stats.invalid++;
            return { valid: false, reason: `Path error: ${pathResult.reason}`, normalized: null };
        }
        // Query
        const queryResult = this.validateQuery(parsed.query || '');
        if (!queryResult.valid) {
            this.stats.invalid++;
            return { valid: false, reason: `Query error: ${queryResult.reason}`, normalized: null };
        }
        // Fragment
        const fragmentResult = this.validateFragment(parsed.hash ? parsed.hash.slice(1) : '');
        if (!fragmentResult.valid) {
            this.stats.invalid++;
            return { valid: false, reason: `Fragment error: ${fragmentResult.reason}`, normalized: null };
        }
        // DNS
        if (this.checkDNS) {
            const dnsOk = await this.checkDNS(parsed.hostname);
            if (!dnsOk) {
                this.stats.invalid++;
                return { valid: false, reason: "Host does not resolve (DNS)", normalized: null };
            }
        }
        // HTTP
        if (this.checkHTTP) {
            const httpOk = await this.checkHTTPAvailability(rawURL);
            if (!httpOk) {
                this.stats.invalid++;
                return { valid: false, reason: "URL is not reachable (HTTP error)", normalized: null };
            }
        }
        this.stats.valid++;
        const normalized = this.normalize(rawURL);
        return { valid: true, reason: "All checks passed", normalized };
    }

    async batchValidate(urls) {
        const results = [];
        for (const u of urls) {
            const url = u.trim();
            if (!url) continue;
            const result = await this.validate(url);
            results.push({ url, ...result });
        }
        return results;
    }

    showStats() {
        console.log(`\nStatistics: Total: ${this.stats.total}, Valid: ${this.stats.valid}, Invalid: ${this.stats.invalid}`);
    }
}

async function main() {
    const validator = new URLValidator(false, false, 5);
    console.log("=== URL Validator ===");
    while (true) {
        console.log("\n1. Validate single URL");
        console.log("2. Validate from file");
        console.log("3. Show statistics");
        console.log(`4. Toggle DNS check (currently ${validator.checkDNS ? 'ON' : 'OFF'})`);
        console.log(`5. Toggle HTTP check (currently ${validator.checkHTTP ? 'ON' : 'OFF'})`);
        console.log("6. Exit");
        const choice = await ask("Choose: ");
        switch (choice.trim()) {
            case '1': {
                const url = await ask("Enter URL: ");
                const result = await validator.validate(url.trim());
                console.log(`Valid: ${result.valid}`);
                console.log(`Details: ${result.reason}`);
                if (result.normalized) console.log(`Normalized: ${result.normalized}`);
                break;
            }
            case '2': {
                const fname = await ask("Enter file path: ");
                try {
                    const fs = require('fs');
                    const data = fs.readFileSync(fname, 'utf8');
                    const urls = data.split('\n');
                    const results = await validator.batchValidate(urls);
                    console.log("\nBatch results:");
                    for (const r of results) {
                        const status = r.valid ? '✓' : '✗';
                        console.log(`${status} ${r.url}: ${r.reason}`);
                        if (r.normalized) console.log(`   Normalized: ${r.normalized}`);
                    }
                } catch (e) {
                    console.log("File not found or error.");
                }
                break;
            }
            case '3':
                validator.showStats();
                break;
            case '4':
                validator.checkDNS = !validator.checkDNS;
                console.log("DNS check toggled.");
                break;
            case '5':
                validator.checkHTTP = !validator.checkHTTP;
                console.log("HTTP check toggled.");
                break;
            case '6':
                console.log("Goodbye!");
                rl.close();
                return;
            default:
                console.log("Invalid choice.");
        }
    }
}

main().catch(console.error);
