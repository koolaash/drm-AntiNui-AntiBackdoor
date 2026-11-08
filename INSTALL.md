# Installation Guide - DRM Scanner

`drm-scanner` is a standalone security, anti-backdoor, and runtime protection resource for FiveM servers. It scans code for known malware/ciphers, intercepts outbound malicious HTTP requests, detects NUI DevTools inspection, and maintains an anti-bypass heartbeat system.

---

## 1. Requirements
- **Dependencies**: None (100% Standalone).
- **Server Artifact**: Recommended FXServer Cerulean (Server Build 3245+).

---

## 2. Installation Steps

### Step 1: Resource Placement
Ensure `drm-scanner` is placed inside your server resources folder:
```
resources/
└── [custom]/
    └── [drm]/
        └── drm-scanner/
            ├── client/
            ├── html/
            ├── server/
            ├── config.json
            ├── malicious_urls.json
            ├── fxmanifest.lua
            ├── INSTALL.md
            └── CONFIG.md
```

### Step 2: Server Configuration (`server.cfg`)
Add `ensure drm-scanner` to your `server.cfg`.

> **Important**: Ensure `drm-scanner` **early** (before starting custom gameplay/script resources). This guarantees that startup code scans and outbound HTTP interception are active before other resources initialize:

```cfg
# Core & System Resources
ensure chat
ensure spawnmanager
ensure sessionmanager

# Security & Anti-Backdoor (Load Early)
ensure drm-scanner

# Other Frameworks & Custom Resources
ensure ox_lib
ensure es_extended # or qb-core / qbx_core
...
```

### Step 3: Add Admin Identifiers
Open `config.json` and add your server administrators to `adminWhitelist` so they are not kicked if they open DevTools or test NUI pages:
```json
"adminWhitelist": [
  "license:45d9f75fc8acd37fb0f5f274564fccfef6c7eda1",
  "discord:294468324115349505"
]
```

---

## 3. Server Console Commands

Run these directly in the server console (txAdmin or server terminal):

| Command | Description |
| :--- | :--- |
| `scancode` | Runs an incremental audit on new and modified resource files. |
| `scancode full` (or `scancode -f`) | Clears the file cache and performs a full scan of all resource files. |

---

## 4. Verification

1. Start or restart the server: `restart drm-scanner` or `ensure drm-scanner`.
2. Check your server console for:
   ```
   [DRM-SCANNER] Outbound HTTP/HTTPS Request Monitor & Firewall Initialized.
   [DRM-SCANNER] Starting Full Scan
   ```
3. Connect in-game with a non-whitelisted account and confirm that normal gameplay runs smoothly with heartbeat pulses registered every 20 seconds.
