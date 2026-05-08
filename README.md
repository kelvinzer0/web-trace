# web-trace

Browser-based HAR recorder for bug bounty hunting. Playwright captures XHR/Fetch/WebSocket traffic → export to Python scripts, cURL, or raw JSON for API exploration and vulnerability testing.

**Anti-detection built-in.** Two-layer stealth: JS fingerprint patches + TLS fingerprint impersonation (JA3/JA4) via curl_cffi. Browser terlihat seperti Chrome asli di level JS maupun network.

---

## Instalasi

```bash
git clone https://github.com/kelvinzer0/web-trace.git
cd web-trace
pip install -r requirements.txt
playwright install chromium   # hanya jika tidak ada Chrome
```

Dependencies:
- `playwright` — browser automation
- `curl_cffi` — TLS fingerprint impersonation (JA3/JA4)

---

## Quick Start

```bash
# Interactive — browser terbuka, browse manual, semua API tercatat
python3 web_trace.py https://target.com

# Hanya record domain API tertentu
python3 web_trace.py https://target.com --scope api.target.com

# Headless + screenshot + simpan HAR
python3 web_trace.py https://target.com --headless --delay 10 --ss --har traffic.har

# Langsung export Python script (dengan TLS impersonation)
python3 web_trace.py https://target.com --headless --delay 8 --export py

# Impersonate Safari (TLS fingerprint beda)
python3 web_trace.py https://target.com --impersonate safari17_0

# Dengan session (cookies tersimpan)
python3 web_trace.py https://target.com --session authed.json
```

---

## Anti-Detection: Dua Layer

### Layer 1: JS Stealth (`stealth.js`)

Patch otomatis aktif. Tanpa flag apapun.

| Deteksi | Proteksi |
|---------|----------|
| `navigator.webdriver` | → `false` |
| `chrome.runtime` | Lengkap (connect, sendMessage, onMessage) |
| `chrome.loadTimes()` | Realistic timing data |
| `chrome.csi()` | Realistic CSI data |
| `navigator.plugins` | Chrome PDF, Viewer, Native Client |
| `navigator.mimeTypes` | PDF mime types |
| WebGL vendor/renderer | Google Inc. (NVIDIA) / ANGLE GTX 1080 |
| Canvas fingerprint | Noise per-domain (imperceptible) |
| AudioContext | Noise pada frequency data |
| ClientRects | ±0.0001px noise |
| Screen | 1920×1080, 24-bit |
| Languages | en-US, en |
| Platform | Konsisten dengan UA |
| Hardware | 8 cores, 8GB RAM |
| Connection | 4G, 10Mbps, rtt 50ms |
| `toString()` | Semua getter → `[native code]` |
| iframe webdriver | `false` |
| CDP artifacts | `cdc_*` dihapus |

### Layer 2: TLS Fingerprint (`curl_cffi`)

Impersonate TLS fingerprint (JA3/JA4) saat export/replay. Request terlihat seperti browser asli di level network.

```bash
# Pilih profile
python3 web_trace.py https://target.com --impersonate chrome120   # default
python3 web_trace.py https://target.com --impersonate safari17_0
python3 web_trace.py https://target.com --impersonate firefox120
```

| Profile | Browser | JA3 Hash |
|---------|---------|----------|
| `chrome120` | Chrome 120 — Win10 | `a9ede20b...` |
| `chrome119` | Chrome 119 — Win10 | `b32309a2...` |
| `chrome116` | Chrome 116 — Win10 | `cd08e314...` |
| `safari17_0` | Safari 17 — macOS | `773906b0...` |
| `safari15_5` | Safari 15.5 — macOS | `a1570295...` |
| `firefox120` | Firefox 120 — Win10 | `b32309a2...` |
| `firefox102` | Firefox 102 ESR | `a3e86288...` |

### Disable Stealth

```bash
# Untuk testing dengan Burp/mitmproxy
python3 web_trace.py https://target.com --proxy http://127.0.0.1:8080 --no-stealth
```

---

## Cara Pakai

### 1. Record Traffic (Interactive)

```bash
python3 web_trace.py https://target.com --scope api.target.com
```

Browser terbuka → **browse manual** (login, klik semua fitur) → API calls muncul real-time:

```
[REC] Recording XHR/Fetch/WebSocket — scope: api.target.com
  GET     200    45ms  /api/user/profile
  POST    200   123ms  /api/quest/claim → ['quest_id'] ← ['ok', 'reward']
  [WS OPEN]  wss://ws.target.com/realtime
  [WS RECV]  {"type":"balance_update","data":{"coins":1500}}
```

Masuk REPL untuk analisis:

```
[trace] > requests          ← lihat semua endpoint
[trace] > auth              ← lihat token yang terdeteksi
[trace] > py exploit.py     ← export Python script (dengan curl_cffi)
[trace] > har traffic.har   ← simpan .har
[trace] > session auth.json ← simpan cookies
[trace] > replay 3          ← replay request #3 dengan TLS impersonation
[trace] > tls safari17_0    ← ganti TLS profile
[trace] > quit
```

### 2. Headless + Auto Export

```bash
# Screenshot + HAR + Python script
python3 web_trace.py https://target.com --headless --delay 10 --ss --har out.har --export py

# Dengan TLS impersonation
python3 web_trace.py https://target.com --headless --delay 8 --export py --impersonate chrome119
```

### 3. Session (Authenticated Testing)

```bash
# Simpan session setelah login manual
python3 web_trace.py https://target.com
[trace] > session authed.json
[trace] > quit

# Load session berikutnya
python3 web_trace.py https://target.com --session authed.json

# Auto-save session
python3 web_trace.py https://target.com --save-session authed.json
```

### 4. Proxy

```bash
# SOCKS5
python3 web_trace.py https://target.com --proxy socks5://127.0.0.1:1080

# Burp Suite
python3 web_trace.py https://target.com --proxy http://127.0.0.1:8080 --no-stealth
```

### 5. Custom UA / Viewport

```bash
# Mobile
python3 web_trace.py https://target.com \
  --ua "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)" \
  --viewport 393x852
```

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
| `py [file]` | Export Python script (curl_cffi + TLS impersonation) |
| `curl [file]` | Export cURL commands |
| `json [file]` | Export JSON dump |
| `replay <id>` | Replay request with TLS impersonation |
| `tls [profile]` | Show/change TLS profile |
| `session [file]` | Save session (cookies + storage) |
| `eval <js>` | Execute JavaScript |
| `dump` | Dump page HTML |
| `clear` | Clear recorded requests |
| `quit` | Exit |

---

## CLI Reference

| Flag | Default | Description |
|------|---------|-------------|
| `url` | (positional) | Target URL |
| `--scope` | semua domain | Filter recording ke domain (repeatable) |
| `--headless` | `false` | Tanpa GUI |
| `--ss` | `false` | Screenshot + exit |
| `--delay` | `5` | Detik tunggu (dengan `--ss`) |
| `--har` | `web_traffic.har` | Output .har path |
| `--export` | `none` | Export: `har` / `py` / `curl` / `json` |
| `--session` | `none` | Load session file |
| `--save-session` | `none` | Simpan session |
| `--ua` | Chrome Win10 | Custom User-Agent |
| `--viewport` | `1280x800` | Viewport `WxH` |
| `--no-stealth` | `false` | Disable JS stealth |
| `--proxy` | `none` | Proxy URL |
| `--timeout` | `60000` | Nav timeout (ms) |
| `--impersonate` | `chrome120` | TLS fingerprint profile |

---

## Export: Python Script

Output dari `py exploit.py` — menggunakan `curl_cffi` dengan TLS impersonation:

```python
#!/usr/bin/env python3
"""
Auto-generated from web-trace recording
TLS fingerprint: chrome120 (Chrome JA3/JA4)
Uses curl_cffi for TLS fingerprint impersonation.
Install: pip install curl_cffi
"""
from curl_cffi.requests import Session
import json

BASE_URL = 'https://api.target.com'

# Auth tokens — auto-detected, replace when expired
AUTHORIZATION = 'Bearer eyJhbGciOiJIUzI1NiIs...'

session = Session(impersonate='chrome120')
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

## Bug Bounty Workflow

```
┌──────────────────────────────────────────────────────────────────┐
│ 1. RECON                                                         │
│    python3 web_trace.py https://target.com \                     │
│      --scope api.target.com --impersonate chrome120              │
│    → Login, browse semua fitur, klik semua tombol                │
│                                                                  │
│ 2. ANALYZE                                                       │
│    [trace] > requests   ← identifikasi semua endpoint            │
│    [trace] > auth       ← catat token/cookie                     │
│    [trace] > ws         ← cek WebSocket messages                 │
│                                                                  │
│ 3. EXPORT                                                        │
│    [trace] > py exploit.py  ← generate Python (curl_cffi)        │
│    [trace] > session auth.json  ← simpan session                 │
│                                                                  │
│ 4. HUNT                                                          │
│    Edit exploit.py:                                              │
│    - Ganti user_id → test IDOR                                   │
│    - Swap token → test BOLA                                      │
│    - Inject payload → test SSRF, SQLi, XSS                      │
│    - Remove auth → test broken auth                              │
│    - Ganti impersonate → test fingerprint-based blocking         │
│                                                                  │
│ 5. REPLAY                                                        │
│    [trace] > replay 5   ← replay request #5 dengan TLS imperson  │
│    [trace] > tls safari17_0  ← ganti fingerprint, coba lagi      │
│                                                                  │
│ 6. REVISIT                                                       │
│    python3 web_trace.py https://target.com --session auth.json   │
└──────────────────────────────────────────────────────────────────┘
```

---

## Arsitektur

```
web-trace/
├── web_trace.py          # Main tool (Chrome launcher + HAR + REPL + export)
├── stealth.js            # Layer 1: JS anti-detection patches
├── tls_fingerprint.py    # Layer 2: TLS impersonation (curl_cffi)
├── requirements.txt      # playwright, curl_cffi
└── README.md
```

### Request Flow

```
┌─────────────────────────────────────────┐
│ Layer 1: JS (stealth.js)                │
│  navigator.webdriver = false             │
│  chrome.runtime, plugins, WebGL, canvas  │
├─────────────────────────────────────────┤
│ Layer 2: TLS (curl_cffi)                │
│  JA3/JA4 = Chrome 120 asli              │
│  HTTP/2 SETTINGS = Chrome 120           │
│  Cipher suites = Chrome 120             │
│  Header ordering = Chrome 120           │
├─────────────────────────────────────────┤
│ Layer 3: Chrome binary (CDP)            │
│  Real Chrome process (bukan Chromium)   │
│  BoringSSL TLS stack                    │
│  Authentic certificate handling         │
└─────────────────────────────────────────┘
```

---

## License

MIT
