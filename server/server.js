const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const http = require('http');
const https = require('https');

const currentRes = GetCurrentResourceName();
const resPath = GetResourcePath(currentRes);

let config = {
    scanOnStartup: true,
    scanOnResourceStart: true,
    startupDelayMs: 1500,
    stopInfectedResources: true,
    enablePeriodicScan: true,
    intervalMinutes: 5,
    monitorHttpRequests: true,
    logOutboundHttp: true,
    maliciousUrlPatterns: ['4rf6.com', 'py.4rf6', 'cipher-panel', 'karmapolicenotdead', 'fivem-backdoor', 'enigma-protect'],
    antiNuiDevTools: true,
    nuiDevToolsKickMessage: 'Security Violation: NUI DevTools is not permitted on this server.',
    enableHeartbeat: true,
    heartbeatTimeoutSeconds: 120,
    heartbeatIntervalSeconds: 20,
    connectGracePeriodSeconds: 120,
    adminWhitelist: [],
    ignoredUrlPatterns: ['github.com', 'raw.githubusercontent.com', 'github.io', 'gitlab.com'],
    whitelistResources: ['drm-scanner', 'monitor', 'txAdmin', 'yarn', 'webpack', 'screenshot-basic'],
    ignoreFolders: ['node_modules', '.git', '.vscode', 'cache', '.system_generated'],
    scanExtensions: ['.lua', '.js', '.ts', '.html', '.htm', '.json']
};

let maliciousPatterns = [];

function loadConfig() {
    try {
        const configRaw = fs.readFileSync(path.join(resPath, 'config.json'), 'utf8');
        config = { ...config, ...JSON.parse(configRaw) };
    } catch (_) {}

    try {
        const fileName = config.maliciousUrlsFile || 'malicious_urls.json';
        const urlsRaw = fs.readFileSync(path.join(resPath, fileName), 'utf8');
        const loadedUrls = JSON.parse(urlsRaw);
        if (Array.isArray(loadedUrls) && loadedUrls.length > 0) {
            maliciousPatterns = loadedUrls;
        }
    } catch (_) {
        if (config.maliciousUrlPatterns && Array.isArray(config.maliciousUrlPatterns)) {
            maliciousPatterns = config.maliciousUrlPatterns;
        }
    }
}

loadConfig();

const fileMtimeCache = new Map();

function getLineNumber(content, index) {
    if (index === undefined || index === null || index < 0) return 1;
    return content.substring(0, index).split('\n').length;
}

const SIGNATURES = [
    {
        id: 'B64_EVAL_BACKDOOR',
        name: 'Base64 Decoded Remote Eval / Function Execution',
        regex: /(Buffer\.from\s*\([^)]+['"]base64['"]\)\.toString\s*\(\s*\)\s*;\s*(?:new\s+Function|eval))/gi,
        isRemoteLoader: false
    },
    {
        id: 'REMOTE_CODE_EXECUTION_EVAL',
        name: 'Remote URL Fetch Piped to eval() or load()',
        regex: /(?:https?\.get|PerformHttpRequest)\s*\([^)]*?(?:eval|new\s+Function|assert\s*\(\s*load|load\s*\(|loadstring\s*\()\s*\(/gis,
        isRemoteLoader: true
    },
    {
        id: 'OBFUSCATED_LOAD_CALL',
        name: 'Obfuscated Global load() Execution',
        regex: /_G\[\s*string\.char\s*\(\s*108\s*,\s*111\s*,\s*97\s*,\s*100\s*\)\s*\]/gi,
        isRemoteLoader: false
    },
    {
        id: 'DECIMAL_OBFUSCATED_LOAD',
        name: 'Decimal Encoded \\108\\111\\97\\100 Execution',
        regex: /\\108\\111\\97\\100/gi,
        isRemoteLoader: false
    },
    {
        id: 'HEX_OBFUSCATED_LOAD',
        name: 'Hex Encoded \\x6c\\x6f\\x61\\x64 Execution',
        regex: /\\x6c\\x6f\\x61\\x64/gi,
        isRemoteLoader: false
    },
    {
        id: 'OBFUSCATED_ASSERT_CALL',
        name: 'Obfuscated Global assert() Execution',
        regex: /_G\[\s*string\.char\s*\(\s*97\s*,\s*115\s*,\s*115\s*,\s*101\s*,\s*114\s*,\s*116\s*\)\s*\]/gi,
        isRemoteLoader: false
    },
    {
        id: 'FONT_IMAGE_STEGANOGRAPHY',
        name: 'Hidden Payload Extracted from Font/Image Asset (.ttf/.png/.jpg)',
        regex: /LoadResourceFile\s*\([^,]+,\s*['"][^'"]+\.(?:ttf|otf|png|jpg|jpeg)['"]\s*\)\s*:\s*sub\s*\(\s*\d+\s*\)/gi,
        isRemoteLoader: false
    },
    {
        id: 'KNOWN_MALICIOUS_HOST',
        name: 'Known Backdoor / Cipher Host Endpoint',
        regex: /(?:4rf6\.com|py\.4rf6|cipher-panel|karmapolicenotdead|fivem-backdoor|enigma-protect)/gi,
        isRemoteLoader: false
    },
    {
        id: 'CREDENTIAL_EXFILTRATION',
        name: 'Unauthorized Server License Key or RCON Exfiltration',
        regex: /(?:(?:GetConvar\s*\(\s*['"]sv_licenseKey['"]|rcon_password)[\s\S]{0,300}?(?:PerformHttpRequest|https?\.request)|(?:PerformHttpRequest|https?\.request)[\s\S]{0,300}?(?:GetConvar\s*\(\s*['"]sv_licenseKey['"]|rcon_password))/gi,
        isRemoteLoader: false
    }
];

function inspectBase64Strings(content) {
    const b64Regex = /["']([A-Za-z0-9+/]{40,}={0,2})["']/g;
    let match;
    const threats = [];
    const ignoredUrls = config.ignoredUrlPatterns || [];

    while ((match = b64Regex.exec(content)) !== null) {
        try {
            const decoded = Buffer.from(match[1], 'base64').toString('utf8');
            const lowerDecoded = decoded.toLowerCase();

            const isIgnored = ignoredUrls.some(url => lowerDecoded.includes(url.toLowerCase()));
            if (isIgnored) continue;

            const isKnownMalicious = maliciousPatterns.some(p => lowerDecoded.includes(p.toLowerCase()));

            if (
                lowerDecoded.includes('https.get') ||
                lowerDecoded.includes('http.get') ||
                lowerDecoded.includes('eval(') ||
                lowerDecoded.includes('performhttprequest') ||
                isKnownMalicious
            ) {
                const line = getLineNumber(content, match.index);
                threats.push({
                    threat: 'Base64 Encoded Network / Code Execution Payload',
                    line: line,
                    snippet: decoded.slice(0, 80).replace(/\s+/g, ' ')
                });
                break;
            }
        } catch (_) {}
    }
    return threats;
}

function testSignatures(content) {
    const threats = [];
    const ignoredUrls = config.ignoredUrlPatterns || [];
    const lowerContent = content.toLowerCase();

    for (const sig of SIGNATURES) {
        const regex = new RegExp(sig.regex.source, sig.regex.flags);
        let match;
        while ((match = regex.exec(content)) !== null) {
            const matchedText = match[0];

            // If signature is remote loader, skip legitimate version checkers (e.g. GitHub, rawgit)
            if (sig.isRemoteLoader) {
                const isIgnored = ignoredUrls.some(url => matchedText.toLowerCase().includes(url.toLowerCase()));
                if (isIgnored) continue;
            }

            const line = getLineNumber(content, match.index);
            threats.push({
                threat: sig.name,
                line: line
            });
            break;
        }
    }

    for (const pattern of maliciousPatterns) {
        if (!pattern || pattern.length < 4) continue;
        const lowerPat = pattern.toLowerCase();
        const foundIdx = lowerContent.indexOf(lowerPat);
        if (foundIdx !== -1) {
            const line = getLineNumber(content, foundIdx);
            threats.push({
                threat: `Known Malicious / Cipher Host: ${pattern}`,
                line: line
            });
            break;
        }
    }

    return threats;
}

function getResourceFiles(dirPath) {
    let files = [];
    try {
        const entries = fs.readdirSync(dirPath, { withFileTypes: true });
        for (const entry of entries) {
            const lowerName = entry.name.toLowerCase();
            const fullPath = path.join(dirPath, entry.name);
            let isDir = entry.isDirectory();
            let isFile = entry.isFile();

            if (entry.isSymbolicLink()) {
                try {
                    const stat = fs.statSync(fullPath);
                    isDir = stat.isDirectory();
                    isFile = stat.isFile();
                } catch (_) {}
            }

            if (isDir) {
                if (config.ignoreFolders.map(f => f.toLowerCase()).includes(lowerName)) {
                    continue;
                }
                files = files.concat(getResourceFiles(fullPath));
            } else if (isFile) {
                const ext = path.extname(lowerName);
                if (
                    config.scanExtensions.includes(ext) ||
                    lowerName === 'fxmanifest.lua' ||
                    lowerName === '__resource.lua'
                ) {
                    files.push(fullPath);
                }
            }
        }
    } catch (_) {}
    return files;
}

function scanResource(resName, isFullScan) {
    let rootPath;
    try {
        rootPath = GetResourcePath(resName);
        if (!rootPath || !fs.existsSync(rootPath)) return { threats: [], modifiedCount: 0 };
    } catch (fsErr) {
        console.log(`^3[DRM-SCANNER] Warning: Filesystem access restricted for '${resName}': ${fsErr.message || fsErr}^7`);
        return { threats: [], modifiedCount: 0 };
    }

    let files = [];
    try {
        files = getResourceFiles(rootPath);
    } catch (filesErr) {
        console.log(`^3[DRM-SCANNER] Warning: Could not read directory for '${resName}': ${filesErr.message || filesErr}^7`);
        return { threats: [], modifiedCount: 0 };
    }

    const threats = [];
    let modifiedCount = 0;

    for (const filePath of files) {
        try {
            const stat = fs.statSync(filePath);
            if (stat.size > 10 * 1024 * 1024) continue;

            const lastMtime = fileMtimeCache.get(filePath);
            const isModified = !lastMtime || stat.mtimeMs > lastMtime;

            if (!isFullScan && !isModified) {
                continue;
            }

            modifiedCount++;
            fileMtimeCache.set(filePath, stat.mtimeMs);

            let content = '';
            // If file is between 2MB and 10MB, inspect head and tail to catch padded payloads
            if (stat.size > 2 * 1024 * 1024) {
                const fd = fs.openSync(filePath, 'r');
                const headBuf = Buffer.alloc(512 * 1024);
                const tailBuf = Buffer.alloc(512 * 1024);
                fs.readSync(fd, headBuf, 0, 512 * 1024, 0);
                const tailPos = Math.max(0, stat.size - 512 * 1024);
                fs.readSync(fd, tailBuf, 0, 512 * 1024, tailPos);
                fs.closeSync(fd);
                content = headBuf.toString('utf8') + '\n' + tailBuf.toString('utf8');
            } else {
                content = fs.readFileSync(filePath, 'utf8');
            }

            const relativePath = path.relative(rootPath, filePath);

            const sigMatches = testSignatures(content);
            sigMatches.forEach(m => {
                threats.push({
                    file: relativePath,
                    line: m.line,
                    threat: m.threat
                });
            });

            const b64Matches = inspectBase64Strings(content);
            b64Matches.forEach(m => {
                threats.push({
                    file: relativePath,
                    line: m.line,
                    threat: m.threat,
                    snippet: m.snippet
                });
            });
        } catch (_) {}
    }

    return { threats, modifiedCount };
}

function handleThreats(resName, threats, triggerContext = 'AUDIT') {
    console.log('^1[DRM-SCANNER] !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!^7');
    console.log(`^1[DRM-SCANNER] [${triggerContext}] BACKDOOR / CIPHER DETECTED IN RESOURCE: ^7^3${resName}^7`);

    threats.forEach(t => {
        console.log(`^1[DRM-SCANNER]   - File: ^7${t.file} ^3(Line ${t.line})^7`);
        console.log(`^1[DRM-SCANNER]     Threat: ^7${t.threat}`);
        if (t.snippet) console.log(`^1[DRM-SCANNER]     Decoded: ^7^3${t.snippet}^7`);
    });

    if (config.stopInfectedResources) {
        try { CancelEvent(); } catch (_) {}
        const stopped = StopResource(resName);
        if (stopped) {
            console.log(`^1[DRM-SCANNER]   -> ACTION: Resource ^3${resName}^1 has been BLOCKED and STOPPED.^7`);
        } else {
            console.log(`^1[DRM-SCANNER]   -> STATUS: Resource ^3${resName}^1 stop command issued.^7`);
        }
    } else {
        console.log(`^3[DRM-SCANNER]   -> NOTICE: Resource stop is disabled in config (stopInfectedResources: false).^7`);
    }
    console.log('^1[DRM-SCANNER] !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!^7');
}

function runSecurityScan(isFullScan = true) {
    loadConfig();

    if (isFullScan) {
        console.log('^3[DRM-SCANNER] ====================================================^7');
        console.log('^3[DRM-SCANNER] Starting Full Server Resource Security Audit...^7');
        console.log('^3[DRM-SCANNER] ====================================================^7');
    }

    const totalResources = GetNumResources();
    let scannedResources = 0;
    let totalModifiedFiles = 0;
    let blockedCount = 0;

    for (let i = 0; i < totalResources; i++) {
        const resName = GetResourceByFindIndex(i);
        if (!resName) continue;

        if (config.whitelistResources.map(r => r.toLowerCase()).includes(resName.toLowerCase())) {
            continue;
        }

        scannedResources++;
        try {
            const { threats = [], modifiedCount = 0 } = scanResource(resName, isFullScan) || {};
            totalModifiedFiles += modifiedCount;

            if (threats && threats.length > 0) {
                blockedCount++;
                handleThreats(resName, threats, 'AUDIT');
            }
        } catch (scanErr) {
            console.log(`^3[DRM-SCANNER] Warning: Skipping '${resName}' due to error during scan: ${scanErr.message || scanErr}^7`);
        }
    }

    if (isFullScan) {
        console.log('^2[DRM-SCANNER] ====================================================^7');
        console.log(`^2[DRM-SCANNER] Scan Complete: ^7Audited ${scannedResources} resources | Blocked ${blockedCount} threats.`);
        console.log('^2[DRM-SCANNER] ====================================================^7');
    } else if (totalModifiedFiles > 0) {
        console.log(`^2[DRM-SCANNER] Live Scan: Checked ${totalModifiedFiles} updated file(s) across resources. Blocked: ${blockedCount}^7`);
    }
}

const recentlyScanned = new Map();

function handleResourceStart(resName) {
    if (!resName) return;

    if (!config.scanOnResourceStart) return;

    // Debounce duplicate start events within 2 seconds
    const now = Date.now();
    if (recentlyScanned.has(resName) && now - recentlyScanned.get(resName) < 2000) {
        return;
    }
    recentlyScanned.set(resName, now);

    if (config.whitelistResources.map(r => r.toLowerCase()).includes(resName.toLowerCase())) {
        return;
    }

    try {
        const result = scanResource(resName, true) || {};
        const threats = result.threats || [];

        if (threats.length > 0) {
            handleThreats(resName, threats, 'STARTUP-INTERCEPT');
        } else {
            console.log(`^2[DRM-SCANNER] Resource ^7^3${resName}^7^2 passed security scan (Clean).^7`);
        }
    } catch (startErr) {
        console.log(`^3[DRM-SCANNER] Warning: Could not scan starting resource '${resName}': ${startErr.message || startErr}^7`);
    }
}

on('onResourceStarting', (resName) => handleResourceStart(resName));
on('onServerResourceStart', (resName) => handleResourceStart(resName));

let httpMonitoringInitialized = false;

function setupHttpMonitoring() {
    if (httpMonitoringInitialized) return;
    if (!config.monitorHttpRequests) return;
    httpMonitoringInitialized = true;

    const originalHttpRequest = http.request;
    const originalHttpsRequest = https.request;
    const originalHttpGet = http.get;
    const originalHttpsGet = https.get;

    function checkUrl(urlInput, defaultProtocol) {
        if (!urlInput) return { isMalicious: false };
        let fullUrl = '';
        if (typeof urlInput === 'string') {
            fullUrl = urlInput;
        } else if (urlInput instanceof URL) {
            fullUrl = urlInput.href;
        } else if (typeof urlInput === 'object') {
            const proto = urlInput.protocol || defaultProtocol || 'http:';
            const host = urlInput.hostname || urlInput.host || '';
            const path = urlInput.path || '';
            fullUrl = `${proto}//${host}${path}`;
        }

        const lowerUrl = fullUrl.toLowerCase();
        let decodedUrl = lowerUrl;
        try {
            decodedUrl = decodeURIComponent(lowerUrl);
        } catch (_) {}

        for (const pattern of maliciousPatterns) {
            if (pattern && pattern.length > 3) {
                const lowerPattern = pattern.toLowerCase();
                if (lowerUrl.includes(lowerPattern) || decodedUrl.includes(lowerPattern)) {
                    return { isMalicious: true, pattern, fullUrl };
                }
            }
        }
        return { isMalicious: false, fullUrl };
    }

    function wrapRequest(originalFn, defaultProtocol) {
        return function(...args) {
            const check = checkUrl(args[0], defaultProtocol);

            if (check.isMalicious) {
                console.log('^1[DRM-SCANNER] !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!^7');
                console.log('^1[DRM-SCANNER] [HTTP-BLOCK] BLOCKED MALICIOUS OUTBOUND HTTP REQUEST!^7');
                console.log(`^1[DRM-SCANNER]   Destination: ^7^3${check.fullUrl}^7`);
                console.log(`^1[DRM-SCANNER]   Matched Pattern: ^7^1${check.pattern}^7`);
                console.log('^1[DRM-SCANNER] !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!^7');

                const mockReq = new (require('events').EventEmitter)();
                mockReq.end = () => mockReq;
                mockReq.write = () => mockReq;
                mockReq.abort = () => mockReq;
                mockReq.destroy = () => mockReq;
                mockReq.setTimeout = () => mockReq;
                setTimeout(() => {
                    if (mockReq.listenerCount('error') > 0) {
                        mockReq.emit('error', new Error(`[DRM-SCANNER] Blocked malicious host: ${check.pattern}`));
                    }
                }, 0);
                return mockReq;
            }

            if (config.logOutboundHttp && check.fullUrl) {
                const isIgnored = (config.ignoredUrlPatterns || []).some(pat => check.fullUrl.toLowerCase().includes(pat.toLowerCase()));
                if (!isIgnored) {
                    console.log(`^5[DRM-SCANNER] [HTTP-MONITOR] Outbound ${defaultProtocol.toUpperCase()}: ^7${check.fullUrl}`);
                }
            }

            return originalFn.apply(this, args);
        };
    }

    http.request = wrapRequest(originalHttpRequest, 'http:');
    https.request = wrapRequest(originalHttpsRequest, 'https:');
    http.get = wrapRequest(originalHttpGet, 'http:');
    https.get = wrapRequest(originalHttpsGet, 'https:');

    if (typeof global.fetch === 'function') {
        const originalFetch = global.fetch;
        global.fetch = async function(resource, options) {
            const check = checkUrl(resource, 'https:');
            if (check.isMalicious) {
                console.log('^1[DRM-SCANNER] !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!^7');
                console.log('^1[DRM-SCANNER] [FETCH-BLOCK] BLOCKED MALICIOUS FETCH REQUEST!^7');
                console.log(`^1[DRM-SCANNER]   Destination: ^7^3${check.fullUrl}^7`);
                console.log(`^1[DRM-SCANNER]   Matched Pattern: ^7^1${check.pattern}^7`);
                console.log('^1[DRM-SCANNER] !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!^7');
                throw new Error(`[DRM-SCANNER] Blocked malicious host: ${check.pattern}`);
            }

            if (config.logOutboundHttp && check.fullUrl) {
                const isIgnored = (config.ignoredUrlPatterns || []).some(pat => check.fullUrl.toLowerCase().includes(pat.toLowerCase()));
                if (!isIgnored) {
                    console.log(`^5[DRM-SCANNER] [FETCH-MONITOR] Outbound Fetch: ^7${check.fullUrl}`);
                }
            }
            return originalFetch.apply(this, arguments);
        };
    }

    if (typeof global.PerformHttpRequest === 'function') {
        const originalPerformHttpRequest = global.PerformHttpRequest;
        global.PerformHttpRequest = function(url, cb, method, data, headers, options) {
            const check = checkUrl(url, 'http:');
            if (check.isMalicious) {
                console.log('^1[DRM-SCANNER] !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!^7');
                console.log('^1[DRM-SCANNER] [PERFORMHTTP-BLOCK] BLOCKED MALICIOUS PerformHttpRequest!^7');
                console.log(`^1[DRM-SCANNER]   Destination: ^7^3${check.fullUrl}^7`);
                console.log(`^1[DRM-SCANNER]   Matched Pattern: ^7^1${check.pattern}^7`);
                console.log('^1[DRM-SCANNER] !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!^7');
                if (typeof cb === 'function') {
                    cb(403, JSON.stringify({ error: `[DRM-SCANNER] Blocked malicious host: ${check.pattern}` }), {});
                }
                return;
            }

            if (config.logOutboundHttp && check.fullUrl) {
                const isIgnored = (config.ignoredUrlPatterns || []).some(pat => check.fullUrl.toLowerCase().includes(pat.toLowerCase()));
                if (!isIgnored) {
                    console.log(`^5[DRM-SCANNER] [HTTP-MONITOR] Outbound PerformHttpRequest: ^7${check.fullUrl}`);
                }
            }

            return originalPerformHttpRequest.apply(this, arguments);
        };
    }

    console.log('^2[DRM-SCANNER] Outbound HTTP/HTTPS & PerformHttpRequest Monitor & Firewall Initialized.^7');
}

function isAdmin(srcInput) {
    if (!config.adminWhitelist || !Array.isArray(config.adminWhitelist) || config.adminWhitelist.length === 0) {
        return false;
    }
    const src = String(srcInput);
    const numIdentifiers = GetNumPlayerIdentifiers(src);
    for (let i = 0; i < numIdentifiers; i++) {
        const id = GetPlayerIdentifier(src, i);
        if (!id) continue;
        const lowerId = id.toLowerCase();
        for (const adminId of config.adminWhitelist) {
            if (!adminId) continue;
            const lowerAdmin = adminId.toString().trim().toLowerCase();
            if (lowerId === lowerAdmin) return true;
            if (lowerId === `discord:${lowerAdmin}`) return true;
            if (lowerId === `license:${lowerAdmin}`) return true;
        }
    }
    return false;
}

const playerHeartbeats = new Map();
const playerConnectTime = new Map();
const playerLoaded = new Map();
const playerSequences = new Map();
const playerNuiSessions = new Map();
// Sliding window of active challenges: src -> Map<challengeId, { token, salt, seq, issuedAt }>
const activeChallenges = new Map();

function cleanupPlayer(src) {
    if (!src) return;
    playerHeartbeats.delete(src);
    playerConnectTime.delete(src);
    playerLoaded.delete(src);
    activeChallenges.delete(src);
    playerNuiSessions.delete(src);
    playerSequences.delete(src);
    lastNuiReadyTime.delete(src);
}

function computeExpectedSignature(token, salt, seq, nuiToken) {
    let hash = 0;
    const combined = String(token) + ':' + String(salt) + ':' + String(seq) + ':' + String(nuiToken);
    for (let i = 0; i < combined.length; i++) {
        hash = ((hash << 5) - hash) + combined.charCodeAt(i);
        hash |= 0;
    }
    return Math.abs(hash).toString(16);
}

function dispatchChallengeToPlayer(src) {
    // Only send challenges to verified, in-game players who have reached the character menu
    if (!src || isAdmin(src) || !GetPlayerName(src) || playerLoaded.get(src) !== true) return;

    let challenges = activeChallenges.get(src);
    if (!challenges) {
        challenges = new Map();
        activeChallenges.set(src, challenges);
    }

    const now = Date.now();
    // Prune challenges older than 120s (generous mobile latency & packet jitter buffer)
    for (const [cId, ch] of challenges.entries()) {
        if (now - ch.issuedAt > 120000) {
            challenges.delete(cId);
        }
    }

    const seq = playerSequences.get(src) || 1;
    const challengeId = crypto.randomBytes(4).toString('hex');
    const token = crypto.randomBytes(8).toString('hex') + now.toString(36);
    const salt = crypto.randomBytes(4).toString('hex');

    challenges.set(challengeId, { token, salt, seq, issuedAt: now });

    TriggerClientEvent('drm-scanner:client:sendChallenge', src, challengeId, token, salt, seq);
}

const lastNuiReadyTime = new Map();

onNet('drm-scanner:server:nuiReady', (nuiToken) => {
    const src = String(source);
    if (!src || src === '0' || !GetPlayerName(src)) return;

    const now = Date.now();
    const lastTime = lastNuiReadyTime.get(src) || 0;
    if (now - lastTime < 5000) return;
    lastNuiReadyTime.set(src, now);

    if (typeof nuiToken !== 'string' || nuiToken.length < 8 || nuiToken.length > 64) {
        return;
    }

    playerNuiSessions.set(src, nuiToken);
    playerSequences.set(src, 1);
    playerHeartbeats.set(src, now);

    dispatchChallengeToPlayer(src);
});

const VALID_DEVTOOLS_DETECTION_METHODS = new Set(['debugger_timing', 'native_function_hooked', 'key_shortcut']);

onNet('drm-scanner:server:nuiDevToolsDetected', (method) => {
    const src = String(source);
    if (!src || src === '0' || !GetPlayerName(src)) return;

    if (!config.antiNuiDevTools) return;

    // Ignore obsolete or false-positive triggers from stale client caches (e.g. regex_tostring)
    if (typeof method !== 'string' || !VALID_DEVTOOLS_DETECTION_METHODS.has(method)) {
        return;
    }

    if (isAdmin(src)) {
        console.log(`^3[DRM-SCANNER] [ANTI-NUI] Admin ${GetPlayerName(src)} (${src}) opened NUI DevTools (${method}) - Allowed (Whitelisted).^7`);
        return;
    }

    const kickMsg = config.nuiDevToolsKickMessage || 'Security Violation: NUI DevTools is not permitted on this server.';
    console.log(`^1[DRM-SCANNER] [ANTI-NUI] KICKED Player ${GetPlayerName(src)} (${src}) - Reason: Opened NUI DevTools (${method})^7`);
    DropPlayer(src, kickMsg);
    cleanupPlayer(src);
});

onNet('drm-scanner:server:playerReady', () => {
    const src = String(source);
    if (!src || src === '0' || !GetPlayerName(src)) return;
    const wasLoaded = playerLoaded.get(src) === true;
    playerLoaded.set(src, true);
    playerHeartbeats.set(src, Date.now());

    // Dispatch first challenge only after the player has reached the character menu
    if (!wasLoaded) {
        dispatchChallengeToPlayer(src);
    }
});

onNet('drm-scanner:server:heartbeatResponse', (data) => {
    const src = String(source);
    if (!src || src === '0' || !GetPlayerName(src)) return;

    if (!data || typeof data !== 'object' || !data.token || !data.signature || typeof data.seq !== 'number') {
        DropPlayer(src, 'Security Violation: Malformed Security Heartbeat Payload');
        cleanupPlayer(src);
        return;
    }

    const challenges = activeChallenges.get(src);
    if (!challenges || challenges.size === 0) {
        return;
    }

    let matchedId = null;
    let pending = null;

    if (data.challengeId && challenges.has(data.challengeId)) {
        matchedId = data.challengeId;
        pending = challenges.get(data.challengeId);
    } else {
        for (const [cId, ch] of challenges.entries()) {
            if (ch.token === data.token) {
                matchedId = cId;
                pending = ch;
                break;
            }
        }
    }

    if (!pending) {
        // Unmatched/expired challenge or duplicate response: silently discard without kicking.
        // If the player is genuinely disconnected or spoofing, the watchdog timer will drop them after timeoutMs.
        return;
    }

    if (data.seq !== pending.seq) {
        console.log(`^1[DRM-SCANNER] [ANTI-SPOOF] Player ${GetPlayerName(src)} (${src}) sequence mismatch (got ${data.seq}, expected ${pending.seq}).^7`);
        DropPlayer(src, 'Security Violation: Invalid Sequence (Replay/Spoof Detected)');
        cleanupPlayer(src);
        return;
    }

    const nuiToken = playerNuiSessions.get(src) || '';
    const expectedSig = computeExpectedSignature(pending.token, pending.salt, pending.seq, nuiToken);
    if (data.signature !== expectedSig) {
        console.log(`^1[DRM-SCANNER] [ANTI-SPOOF] Player ${GetPlayerName(src)} (${src}) submitted forged heartbeat signature.^7`);
        DropPlayer(src, 'Security Violation: Forged Security Heartbeat Signature (Executor Spoof Detected)');
        cleanupPlayer(src);
        return;
    }

    challenges.delete(matchedId);
    playerSequences.set(src, pending.seq + 1);
    playerHeartbeats.set(src, Date.now());
});

on('playerJoining', () => {
    const src = String(source);
    const now = Date.now();
    playerConnectTime.set(src, now);
    playerHeartbeats.set(src, now);
    playerSequences.set(src, 1);
    playerLoaded.set(src, false);
});

on('playerDropped', () => {
    const src = String(source);
    cleanupPlayer(src);
});

let heartbeatWatchdogTimer = null;
let challengeDispatcherTimer = null;

function setupHeartbeatWatchdog() {
    if (heartbeatWatchdogTimer) clearInterval(heartbeatWatchdogTimer);
    if (challengeDispatcherTimer) clearInterval(challengeDispatcherTimer);
    if (!config.enableHeartbeat) return;

    // Initialize any players currently online (handles resource restart safely)
    const existingPlayers = getPlayers();
    const initTime = Date.now();
    for (const p of existingPlayers) {
        const src = String(p);
        if (!src || !GetPlayerName(src)) continue;
        if (!playerConnectTime.has(src)) playerConnectTime.set(src, initTime);
        if (!playerHeartbeats.has(src)) playerHeartbeats.set(src, initTime);
        if (!playerSequences.has(src)) playerSequences.set(src, 1);
        playerLoaded.set(src, true);
    }
    TriggerClientEvent('drm-scanner:client:requestRehandshake', -1);

    const intervalSec = config.heartbeatIntervalSeconds || 20;
    const timeoutMs = (config.heartbeatTimeoutSeconds || 120) * 1000;

    // Dispatch rolling challenges every interval (strictly only to players who have loaded into the character menu / game)
    challengeDispatcherTimer = setInterval(() => {
        const players = getPlayers();
        for (const p of players) {
            const src = String(p);
            if (!src || isAdmin(src) || !GetPlayerName(src) || playerLoaded.get(src) !== true) continue;
            dispatchChallengeToPlayer(src);
        }
    }, intervalSec * 1000);

    heartbeatWatchdogTimer = setInterval(() => {
        const now = Date.now();
        const players = getPlayers();

        for (const p of players) {
            const src = String(p);
            if (!src || isAdmin(src) || !GetPlayerName(src)) continue;

            // Never monitor or kick players who are still in the loading screen / asset download!
            // Heartbeat tracking strictly begins once the player enters the character menu.
            if (playerLoaded.get(src) !== true) {
                continue;
            }

            const lastBeat = playerHeartbeats.get(src) || now;
            const elapsed = now - lastBeat;

            if (elapsed > timeoutMs) {
                const pName = GetPlayerName(src) || 'Unknown';
                console.log(`^1[DRM-SCANNER] [HEARTBEAT-WATCHDOG] KICKED Player ${pName} (${src}) - Missing verified heartbeat (${Math.round(elapsed / 1000)}s without pulse).^7`);
                DropPlayer(src, 'Security Violation: Security Heartbeat Timeout (Desync / Tamper Detected)');
                cleanupPlayer(src);
            }
        }
    }, 5000);
}

let periodicTimer = null;
function setupPeriodicScan() {
    if (periodicTimer) clearInterval(periodicTimer);
    if (!config.enablePeriodicScan) return;

    const intervalMs = Math.max(1, config.intervalMinutes || 5) * 60 * 1000;
    periodicTimer = setInterval(() => {
        runSecurityScan(false);
    }, intervalMs);
}

setupHttpMonitoring();
setupHeartbeatWatchdog();

if (config.scanOnStartup) {
    setTimeout(() => {
        runSecurityScan(true);
        setupPeriodicScan();
    }, config.startupDelayMs || 1500);
} else {
    setupPeriodicScan();
}

RegisterCommand('scancode', (source, args) => {
    if (source === 0) {
        const isFull = args[0] && (args[0].toLowerCase() === 'full' || args[0].toLowerCase() === '-f');
        if (isFull) {
            fileMtimeCache.clear();
            runSecurityScan(true);
        } else {
            console.log('^3[DRM-SCANNER] Running incremental check for new or modified files... (Use `scancode full` for complete re-scan)^7');
            runSecurityScan(false);
        }
    } else {
        console.log(`^1[DRM-SCANNER] 'scancode' can only be executed from the server console.^7`);
    }
}, true);
