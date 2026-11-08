# Configuration Reference - DRM Scanner

All configuration options are defined in `config.json`. Changes to this file take effect immediately or upon running `restart drm-scanner`.

---

## Configuration Keys

```json
{
  "scanOnStartup": true,
  "scanOnResourceStart": true,
  "startupDelayMs": 1500,
  "stopInfectedResources": true,
  "enablePeriodicScan": true,
  "intervalMinutes": 5,
  "monitorHttpRequests": true,
  "logOutboundHttp": true,
  "maliciousUrlsFile": "malicious_urls.json",
  "antiNuiDevTools": true,
  "nuiDevToolsKickMessage": "Security Violation: NUI DevTools is not permitted on this server.",
  "enableHeartbeat": true,
  "heartbeatTimeoutSeconds": 120,
  "heartbeatIntervalSeconds": 20,
  "connectGracePeriodSeconds": 120,
  "adminWhitelist": [
    "license:45d9f75fc8acd37fb0f5f274564fccfef6c7eda1",
    "discord:294468324115349505"
  ],
  "ignoredUrlPatterns": [
    "github.com",
    "raw.githubusercontent.com",
    "github.io",
    "gitlab.com"
  ],
  "whitelistResources": [
    "drm-scanner",
    "monitor",
    "txAdmin",
    "yarn",
    "webpack",
    "screenshot-basic"
  ],
  "ignoreFolders": [
    "node_modules",
    ".git",
    ".vscode",
    "cache",
    ".system_generated"
  ],
  "scanExtensions": [
    ".lua",
    ".js",
    ".ts",
    ".html",
    ".htm",
    ".json"
  ]
}
```

---

## Detailed Option Descriptions

### 1. Code Scanner & Anti-Backdoor Audit
| Key | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `scanOnStartup` | `boolean` | `true` | Runs an automatic scan across resources when FXServer starts. |
| `scanOnResourceStart` | `boolean` | `true` | Intercepts resource startups (`onResourceStarting`) and scans files before execution. |
| `startupDelayMs` | `number` | `1500` | Delay in milliseconds before launching initial startup scan. |
| `stopInfectedResources` | `boolean` | `true` | Automatically stops and blocks any resource where malicious code/backdoors are detected. |
| `enablePeriodicScan` | `boolean` | `true` | Periodically scans for modified or newly added files across resources. |
| `intervalMinutes` | `number` | `5` | Frequency in minutes for the periodic background audit. |
| `ignoreFolders` | `array` | `[...]` | Directories excluded from file crawling (e.g. `node_modules`, `.git`). |
| `scanExtensions` | `array` | `[...]` | File extensions inspected during security audits. |
| `whitelistResources` | `array` | `[...]` | Resources completely bypassed from the code scanner. |

---

### 2. Outbound HTTP Firewall (Escrow & Backdoor Protection)
| Key | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `monitorHttpRequests` | `boolean` | `true` | Hooks outgoing HTTP, HTTPS, Fetch, and FiveM `PerformHttpRequest` calls from server scripts. |
| `logOutboundHttp` | `boolean` | `true` | Prints outgoing HTTP request destinations to the server console for audit trails. |
| `maliciousUrlsFile` | `string` | `"malicious_urls.json"` | Dedicated JSON database containing 175+ threat/cipher/backdoor domains. |
| `ignoredUrlPatterns` | `array` | `[...]` | Benign domains (e.g. GitHub releases) suppressed from verbose HTTP logs. |

---

### 3. Anti-NUI DevTools Detection
| Key | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `antiNuiDevTools` | `boolean` | `true` | Enables in-game NUI DevTools inspection detection. |
| `nuiDevToolsKickMessage` | `string` | `"..."` | The disconnect message displayed to players when dropped for opening DevTools. |

---

### 4. Anti-Bypass Heartbeat System
| Key | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `enableHeartbeat` | `boolean` | `true` | Enables watchdog tracking of client/NUI heartbeat pulses once the player has reached character select / loaded. |
| `heartbeatTimeoutSeconds` | `number` | `120` | If a non-whitelisted in-game player sends no heartbeat for this long, they are dropped. |
| `heartbeatIntervalSeconds` | `number` | `20` | Interval in seconds at which the client NUI sends heartbeat pulses. |
| `connectGracePeriodSeconds` | `number` | `120` | Grace period granted to newly connecting players. (Loading screen players are fully exempt from heartbeat kicks). |

---

### 5. Admin Whitelist
| Key | Type | Description |
| :--- | :--- | :--- |
| `adminWhitelist` | `array` | List of FiveM `license:` or `discord:` identifiers exempt from DevTools and heartbeat enforcement. |

#### Formatting Examples:
```json
"adminWhitelist": [
  "license:45d9f75fc8acd37fb0f5f274564fccfef6c7eda1",
  "discord:294468324115349505"
]
```
*(Identifiers can be provided with or without the `license:` / `discord:` prefix; both are recognized).*
