# web-trace

Browser-based HAR recorder for bug bounty hunting. Playwright captures XHR/Fetch/WebSocket traffic → export to Python scripts, cURL, or raw JSON for API exploration and vulnerability testing.

No Telegram dependencies. Pure web traffic recording.

---

## Fitur

| Category | Detail |
|----------|--------|
| **Browser** | Real Chrome via CDP (authentic TLS fingerprint) or bundled Chromium |
| **Recording** | XHR, Fetch, WebSocket — request + response + headers + body |
| **Export** | `.har`, Python `requests` script, cURL commands, JSON dump |
| **REPL** | Interactive: browse, click, record, export, replay — all in one session |
| **Scope Filter** | Record only specific domains (`--scope example.com`) |
| **Auth Capture** | Auto-detect `Authorization`, `X-API-Key`, cookies from traffic |
| **Session Save** | Save/load cookies + localStorage for authenticated testing |
| **Headless** | Run without GUI for CI/CD or scripted captures |
| **Multi-Tab** | Track requests across tabs |
| **Request Replay** | Replay captured requests with modifications |

---

## Instalasi

```bash
# Clone
git clone https://github.com/kelvinzer0/web-trace.git
cd web-trace

# Dependencies
pip install -r requirements.txt

# Browser (jika tidak ada Chrome)
playwright install chromium
```

---

## Quick Start

```bash
# Buka browser, record semua XHR/Fetch/WebSocket
python3 web_trace.py https://target.com

# Headless + screenshot + simpan HAR
python3 web_trace.py https://target.com --headless --ss --har out.har

# Hanya record domain tertentu
python3 web_trace.py https://target.com --scope api.target.com

# Export langsung ke Python script
python3 web_trace.py https://target.com --export py

# Load session sebelumnya (cookies)
python3 web_trace.py https://target.com --session saved_session.json
```

---

## CLI Reference

| Flag | Default | Description |
|------|---------|-------------|
| `url` | (positional) | Target URL untuk dibuka |
| `--scope` | semua domain | Filter recording ke domain tertentu (bisa multi: `--scope a.com --scope b.com`) |
| `--headless` | `false` | Tanpa GUI |
| `--ss` | `false` | Screenshot + exit (setelah delay) |
| `--delay` | `5` | Detik tunggu sebelum exit (untuk `--ss`) |
| `--har` | `web_traffic.har` | Output .har file path |
| `--export` | `none` | Export format: `har` / `py` / `curl` / `json` |
| `--session` | `none` | Load session file (cookies + localStorage) |
| `--save-session` | `none` | Simpan session setelah selesai |
| `--ua` | auto | Custom User-Agent string |
| `--viewport` | `1280x800` | Viewport size (`WxH`) |
| `--no-stealth` | `false` | Disable stealth patches |
| `--proxy` | `none` | Proxy (`socks5://host:port` or `http://host:port`) |
| `--timeout` | `60000` | Navigation timeout (ms) |

---

## Interactive REPL

Setelah browser terbuka, masuk REPL mode:

```
┌─ web-trace REPL ─────────────────────────────────────────┐
│  info           Page info (text, buttons, links)          │
│  ss             Screenshot                                │
│  click <text>   Click element by text                     │
│  type <sel> <v> Type into selector                        │
│  scroll         Scroll down                               │
│  nav <url>      Navigate to URL                           │
│  tab            List open tabs                            │
│  newtab <url>   Open new tab                              │
│  requests       Show captured requests                    │
│  auth           Show detected auth headers/tokens         │
│  ws             Show WebSocket connections                │
│  har [file]     Save HAR                                  │
│  py [file]      Export Python script                      │
│  curl [file]    Export cURL commands                      │
│  json [file]    Export JSON dump                          │
│  replay <id>    Replay a captured request                 │
│  session [file] Save session (cookies + storage)          │
│  eval <js>      Execute JavaScript                        │
│  dump           Dump page HTML                            │
│  clear          Clear recorded requests                   │
│  quit           Exit                                      │
└───────────────────────────────────────────────────────────┘
```

### Contoh REPL Session

```bash
# Lihat semua API calls yang tercapture
[trace] > requests
  GET     200   45ms  /api/user/profile
  POST    200  123ms  /api/quest/claim → ['quest_id'] ← ['ok', 'reward']
  GET     200   67ms  /api/leaderboard?page=1

# Lihat auth tokens yang terdeteksi
[trace] > auth
  Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
  X-API-Key: sk-abc123def456
  Cookie: session_id=xyz789

# Export ke Python script
[trace] > py exploit.py
  💾 Exported: exploit.py (5 endpoints)

# Replay request ke-3 dengan payload berbeda
[trace] > replay 3
  → Akan minta input untuk modify headers/body sebelum send
```

---

## Export: Python Script

Output script siap pakai untuk automation/exploit:

```python
#!/usr/bin/env python3
"""
Auto-generated from web-trace recording
Date: 2026-05-08 13:00:00
Endpoints: 5 | Domains: 1
"""

import requests
import json

BASE_URL = 'https://api.target.com'

# Auth headers — auto-detected from traffic
AUTHORIZATION = 'Bearer eyJhbGciOiJIUzI1NiIs...'

session = requests.Session()
session.headers.update({
    'Authorization': AUTHORIZATION,
})

def api_user_profile(session=session):
    """
    GET /api/user/profile
    Status: 200 | Duration: 45ms
    """
    url = f'{BASE_URL}/api/user/profile'
    resp = session.get(url)
    resp.raise_for_status()
    return resp.json()

def api_quest_claim(session=session):
    """
    POST /api/quest/claim
    Status: 200 | Duration: 123ms
    """
    url = f'{BASE_URL}/api/quest/claim'

    # ⬇️ Edit payload
    payload = {
        'quest_id': 'daily_login',  # ← edit
        'timestamp': 1713254400,    # ← edit
    }

    resp = session.post(url, json=payload)
    resp.raise_for_status()
    return resp.json()

if __name__ == '__main__':
    results = {}

    # results['user_profile'] = api_user_profile()
    # print(json.dumps(results['user_profile'], indent=2))

    # results['quest_claim'] = api_quest_claim()
    # print(json.dumps(results['quest_claim'], indent=2))

    pass
```

---

## Bug Bounty Workflow

```
┌──────────────────────────────────────────────────────────────┐
│  1. Record: python3 web_trace.py https://target.com          │
│     → Login, browse semua fitur, klik-klik                   │
│     ↓                                                        │
│  2. Analyze: REPL → requests → auth                          │
│     → Identifikasi API endpoints, auth flow, params          │
│     ↓                                                        │
│  3. Export: py exploit.py                                    │
│     → Dapat Python script siap edit                          │
│     ↓                                                        │
│  4. Hunt: Edit script → test IDOR, SSRF, BOLA, dll          │
│     → Modify user_id, swap tokens, inject payloads          │
│     ↓                                                        │
│  5. Save session untuk revisit                                │
│     → --save-session authed.json                             │
└──────────────────────────────────────────────────────────────┘
```

---

## Arsitektur

```
web_trace.py
├── ChromeLauncher          # Find & launch Chrome/Chromium
│   ├── _find_chrome()      # Detect real Chrome binary
│   ├── _launch_cdp()       # Launch via CDP (real TLS)
│   └── _launch_fallback()  # Bundled Chromium + stealth
├── HARRecorder             # Network traffic capture
│   ├── _on_request()       # Capture XHR/Fetch requests
│   ├── _on_response()      # Capture responses
│   ├── _on_websocket()     # Capture WS connections + messages
│   ├── to_har()            # Export HAR 1.2 format
│   ├── to_python()         # Generate Python requests script
│   ├── to_curl()           # Generate cURL commands
│   └── detect_auth()       # Auto-detect auth headers/tokens
├── SessionManager          # Save/load cookies + localStorage
│   ├── save()              # Export session state
│   └── load()              # Import session state
├── WebTrace                # Main orchestrator
│   ├── start()             # Launch browser + attach recorder
│   ├── screenshot()        # Capture screenshot
│   ├── interactive()       # REPL loop
│   └── close()             # Cleanup
└── main()                  # CLI entry point
```

---

## License

MIT
