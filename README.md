<p align="center">
  <img src="Thumbnail - Security Scanner.png" alt="Dream Security Scanner - Anti-Backdoor & Anti-NUI" width="100%">
</p>

# DRM Security & Anti-Backdoor Scanner

A standalone FiveM resource that scans your other resources for backdoors, blocks outbound requests to known malicious hosts, and kicks players who open NUI DevTools.

## What it does

- Scans resource files at startup and on a timer for obfuscated `load()` calls, base64 payloads and similar backdoor patterns. Infected resources are stopped.
- Watches server-side HTTP calls (`PerformHttpRequest`, `fetch`, http/https) and drops requests to hosts listed in `malicious_urls.json`.
- Detects NUI DevTools on the client and kicks the player unless they are whitelisted.
- Runs a challenge-response heartbeat between server and client to catch spoofed or disconnected clients.
- Needs no other resources. Works with ESX, QBCore, Qbox or standalone.

## Setup

1. Put the folder in your `resources` directory and name it `drm-scanner`.
2. Add it near the top of your `server.cfg`:
   ```cfg
   ensure drm-scanner
   ```
3. Add your admin identifiers to `adminWhitelist` in `config.json`.
4. Restart the server.

More in [INSTALL.md](INSTALL.md) and [CONFIG.md](CONFIG.md).

## Credits

| | |
|---|---|
| **Store** | [dreamscripts.shop](https://www.dreamscripts.shop/) |
| **Dream Script Discord** | [Join (support & community)](https://discord.gg/nkMTBARzz4) |
| **GitHub** | [koolaash](https://github.com/koolaash) |
| **Portfolio** | [dreamscripting.vercel.app](https://dreamscripting.vercel.app/) |
| **Personal Discord** | [Join](https://discord.gg/BgDzU5AcA2) |