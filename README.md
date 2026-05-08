# web-trace

Browser-based HAR recorder for bug bounty hunting. Playwright captures XHR/Fetch/WebSocket traffic → export to Python scripts, cURL, or raw JSON for API exploration and vulnerability testing.

**Anti-detection built-in.** Stealth patches remove automation fingerprints — browser terlihat seperti Chrome biasa, bukan Playwright/Puppeteer.

---

## Instalasi

```bash
git clone https://github.com/kelvinzer0/web-trace.git
cd web-trace
pip install -r requirements.txt
playwright install chromium   # hanya jika tidak ada Chrome
```

---

## Cara Pakai

### 1. Record Traffic (Interactive)

```bash
# Buka target, browse manual, semua XHR/Fetch/WebSocket tercatat
python3 web_trace.py https://target.com

# Filter hanya domain API
python3 web_trace.py https://target.com --scope api.target.com

# Multiple scope
python3 web_trace.py https://target.com --scope api.target.com --scope cdn.target.com
```

Setelah browser terbuka, **browse manual** (login, klik-klik semua fitur). Setiap API call muncul real-time di terminal:

```
[REC] Recording XHR/Fetch/WebSocket — scope: api.target.com
  GET     200    45ms  /api/user/profile
  POST    200   123ms  /api/quest/claim → ['quest_id'] ← ['ok', 'reward']
  GET     200    67ms  /api/leaderboard?page=1
  [WS OPEN]  wss://ws.target.com/realtime
  [WS RECV]  {"type":"balance_update","data":{"coins":1500}}
```

Lalu masuk **REPL** untuk analisis & export:

```
[trace] > requests          ← lihat semua API calls
[trace] > auth              ← lihat token yang terdeteksi
[trace] > py exploit.py     ← export ke Python script
[trace] > curl cmds.sh      ← export ke cURL
[trace] > har traffic.har   ← simpan .har file
[trace] > session auth.json ← simpan cookies + localStorage
[trace] > quit
```

### 2. Headless + Auto Export

```bash
# Buka target, tunggu 10 detik, screenshot, simpan HAR, keluar
python3 web_trace.py https://target.com --headless --delay 10 --ss --har traffic.har

# Headless + langsung export Python script
python3 web_trace.py https://target.com --headless --delay 8 --export py --har traffic.har
```

### 3. Dengan Session (Authenticated Testing)

```bash
# Step 1: Login manual, simpan session
python3 web_trace.py https://target.com
[trace] > session authed.json
[trace] > quit

# Step 2: Load session berikutnya (tidak perlu login ulang)
python3 web_trace.py https://target.com --session authed.json

# Step 3: Atau auto-save session di akhir
python3 web_trace.py https://target.com --save-session authed.json
```

### 4. Dengan Proxy

```bash
# SOCKS5
python3 web_trace.py https://target.com --proxy socks5://127.0.0.1:1080

# HTTP proxy
python3 web_trace.py https://target.com --proxy http://127.0.0.1:8080

# Burp Suite (intercept traffic)
python3 web_trace.py https://target.com --proxy http://127.0.0.1:8080 --no-stealth
```

### 5. Custom User-Agent & Viewport

```bash
# Mobile simulation
python3 web_trace.py https://target.com \
  --ua "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15" \
  --viewport 393x852

# Desktop ultrawide
python3 web_trace.py https://target.com --viewport 2560x1440
```

---

## Anti-Detection (Stealth)

Stealth patches aktif secara otomatis. Termasuk:

| Layer | Proteksi |
|-------|----------|
| **navigator.webdriver** | Dihapus (false/undefined) |
| **Chrome object** | chrome.runtime, chrome.loadTimes, chrome.csi — lengkap |
| **Plugins** | Chrome PDF Plugin, Chrome PDF Viewer, Native Client |
| **Permissions API** | Notifications konsisten dengan browser asli |
| **WebGL** | Vendor/renderer di-spoof ke Google Inc. (NVIDIA) |
| **Canvas** | Noise imperceptible pada toDataURL |
| **AudioContext** | Noise pada frequency data |
| **ClientRects** | Noise ±0.0001px (tidak terlihat manusia) |
| **Screen** | 1920×1080, colorDepth 24 |
| **Languages** | en-US, en |
| **Platform** | Konsisten dengan User-Agent |
| **Hardware** | 8 cores, 8GB RAM |
| **Connection** | 4G, 10Mbps, rtt 50ms |
| **SpeechSynthesis** | Realistic voice list |
| **MediaDevices** | Minimal device list |
| **toString()** | Semua getter → `[native code]` |
| **iframe** | webdriver dihapus di iframe juga |
| **CDP artifacts** | cdc_* properties dihapus |

### Disable Stealth

```bash
# Untuk testing dengan Burp/mitmproxy (stealth bisa interfere)
python3 web_trace.py https://target.com --proxy http://127.0.0.1:8080 --no-stealth
```

---

## CLI Reference

| Flag | Default | Description |
|------|---------|-------------|
| `url` | (positional) | Target URL |
| `--scope` | semua domain | Filter recording ke domain tertentu (repeatable) |
| `--headless` | `false` | Tanpa GUI |
| `--ss` | `false` | Screenshot + exit (setelah delay) |
| `--delay` | `5` | Detik tunggu sebelum exit (dengan `--ss`) |
| `--har` | `web_traffic.har` | Output .har file path |
| `--export` | `none` | Export format: `har` / `py` / `curl` / `json` |
| `--session` | `none` | Load session file (cookies + storage) |
| `--save-session` | `none` | Simpan session setelah selesai |
| `--ua` | Chrome Win10 | Custom User-Agent |
| `--viewport` | `1280x800` | Viewport size (`WxH`) |
| `--no-stealth` | `false` | Disable stealth patches |
| `--proxy` | `none` | Proxy (`socks5://host:port` or `http://host:port`) |
| `--timeout` | `60000` | Navigation timeout (ms) |

---

## Interactive REPL

| Command | Description |
|---------|-------------|
| `info` | Page info (text, buttons, links) |
| `ss` | Screenshot |
| `click <text>` | Click element by text |
| `type <selector> <value>` | Type into selector |
| `scroll` | Scroll down |
| `nav <url>` | Navigate to URL |
| `requests` | Show captured requests + summary |
| `auth` | Show detected auth headers/tokens |
| `ws` | Show WebSocket connections |
| `har [file]` | Save HAR |
| `py [file]` | Export Python script |
| `curl [file]` | Export cURL commands |
| `json [file]` | Export JSON dump |
| `session [file]` | Save session (cookies + storage) |
| `eval <js>` | Execute JavaScript |
| `dump` | Dump page HTML |
| `clear` | Clear recorded requests |
| `quit` | Exit |

---

## Bug Bounty Workflow

```
┌────────────────────────────────────────────────────────────────┐
│ 1. RECON                                                       │
│    python3 web_trace.py https://target.com \                   │
│      --scope api.target.com --scope ws.target.com              │
│    → Login, browse semua fitur, klik semua tombol              │
│                                                                │
│ 2. ANALYZE                                                     │
│    [trace] > requests   ← identifikasi semua endpoint          │
│    [trace] > auth       ← catat token/cookie                   │
│    [trace] > ws         ← cek WebSocket messages               │
│                                                                │
│ 3. EXPORT                                                      │
│    [trace] > py exploit.py  ← generate Python script           │
│    [trace] > session auth.json  ← simpan session               │
│                                                                │
│ 4. HUNT                                                        │
│    Edit exploit.py:                                            │
│    - Ganti user_id → test IDOR                                 │
│    - Swap token → test BOLA                                    │
│    - Inject payload → test SSRF, SQLi, XSS                    │
│    - Remove auth → test broken auth                            │
│    - Replay tanpa session → test rate limiting                 │
│                                                                │
│ 5. REVISIT                                                     │
│    python3 web_trace.py https://target.com --session auth.json │
│    → Tidak perlu login ulang                                   │
└────────────────────────────────────────────────────────────────┘
```

---

## Arsitektur

```
web-trace/
├── web_trace.py        # Main tool (Chrome launcher + HAR recorder + REPL + export)
├── stealth.js          # Anti-detection patches (loaded at runtime)
├── requirements.txt    # playwright>=1.40.0
└── README.md
```

---

## Export Contoh: Python Script

Output dari `[trace] > py exploit.py`:

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

# Auth tokens — auto-detected, replace when expired
AUTHORIZATION = 'Bearer eyJhbGciOiJIUzI1NiIs...'

session = requests.Session()
session.headers.update({
    'Authorization': AUTHORIZATION,
})

def api_user_profile(session=session):
    """GET /api/user/profile — 200, 45ms"""
    url = f'{BASE_URL}/api/user/profile'
    resp = session.get(url)
    resp.raise_for_status()
    return resp.json()

def api_quest_claim(session=session):
    """POST /api/quest/claim — 200, 123ms"""
    url = f'{BASE_URL}/api/quest/claim'
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

## License

MIT
