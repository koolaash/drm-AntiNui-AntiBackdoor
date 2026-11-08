# Install

No dependencies. FXServer Cerulean (build 3245 or newer) is recommended.

## 1. Add the resource

Copy the folder into `resources` and keep the name `drm-scanner`. The default `whitelistResources` in `config.json` and the event names use that name, so a different folder name can make the scanner check itself.

```text
drm-scanner/
├── client/client.lua
├── html/index.html
├── html/index.js
├── server/server.js
├── config.json
├── malicious_urls.json
└── fxmanifest.lua
```

## 2. Add it to server.cfg

Start it before your other scripts so the HTTP monitor and startup scan are active when they load.

```cfg
ensure chat
ensure spawnmanager
ensure sessionmanager

ensure drm-scanner

ensure ox_lib
ensure es_extended # or qb-core / qbx_core
```

## 3. Whitelist your admins

Add your staff to `adminWhitelist` in `config.json` so they aren't kicked for opening DevTools:

```json
"adminWhitelist": [
  "license:your_license_hash",
  "discord:your_discord_id"
]
```

A bare Discord ID also works.

## Console commands

Server console only.

| Command | Description |
| :--- | :--- |
| `scancode` | Checks files that are new or changed since the last scan. |
| `scancode full` or `scancode -f` | Clears the cache and scans everything. |

## Check that it works

Restart the resource and look for these in the console:

```text
[DRM-SCANNER] Outbound HTTP/HTTPS & PerformHttpRequest Monitor & Firewall Initialized.
[DRM-SCANNER] Starting Full Scan
```