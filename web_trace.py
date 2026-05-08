#!/usr/bin/env python3
"""
web-trace — Browser-based HAR recorder for bug bounty hunting.

Captures XHR/Fetch/WebSocket traffic via Playwright.
Export to Python scripts, cURL, HAR, or JSON for API exploration.

Usage:
    python3 web_trace.py https://target.com
    python3 web_trace.py https://target.com --scope api.target.com --export py
    python3 web_trace.py https://target.com --headless --ss --har out.har
"""

import asyncio
import json
import argparse
import os
import re
import shutil
import socket
import subprocess
import time
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path

from playwright.async_api import async_playwright

# Optional: curl_cffi for TLS fingerprint impersonation
try:
    from tls_fingerprint import TLSClient, ALL_PROFILES, CHROME_PROFILES
    HAS_CURL_CFFI = True
except ImportError:
    HAS_CURL_CFFI = False


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Chrome Launcher
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

CHROME_CANDIDATES = [
    "/usr/bin/google-chrome-stable",
    "/usr/bin/google-chrome",
    "/usr/bin/google-chrome-beta",
    "/usr/bin/chromium-browser",
    "/usr/bin/chromium",
    "/snap/bin/chromium",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    os.path.expanduser(r"~\AppData\Local\Google\Chrome\Application\chrome.exe"),
]

STEALTH_FLAGS = [
    "--disable-blink-features=AutomationControlled",
    "--disable-features=AutomationControlled",
    "--no-sandbox",
    "--disable-setuid-sandbox",
    "--disable-infobars",
    "--disable-dev-shm-usage",
    "--disable-gpu",
    "--disable-extensions",
    "--disable-background-networking",
    "--disable-default-apps",
    "--disable-sync",
    "--metrics-recording-only",
    "--no-first-run",
    "--safebrowsing-disable-auto-update",
    "--password-store=basic",
    "--use-mock-keychain",
    "--enable-features=NetworkService,NetworkServiceInProcess",
    "--force-color-profile=srgb",
]

def _load_stealth_js() -> str:
    """Load stealth.js from the same directory as this script."""
    stealth_path = Path(__file__).parent / "stealth.js"
    if stealth_path.exists():
        return stealth_path.read_text()
    # Fallback minimal stealth
    return """
    Object.defineProperty(navigator, 'webdriver', { get: () => false });
    window.chrome = window.chrome || { runtime: {}, loadTimes: function(){}, csi: function(){} };
    """


def _find_chrome():
    """Find Chrome/Chromium binary."""
    for path in CHROME_CANDIDATES:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    for name in ["google-chrome-stable", "google-chrome", "chromium-browser", "chromium"]:
        found = shutil.which(name)
        if found:
            return found
    return None


def _free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# HAR Recorder
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class NetworkEntry:
    """Single captured request/response."""
    __slots__ = (
        "seq", "type", "method", "url", "status", "status_text",
        "request_headers", "request_body", "response_headers", "response_body",
        "content_type", "start_time", "end_time", "duration_ms",
        "ws_messages", "failed",
    )

    def __init__(self, seq: int, entry_type: str):
        self.seq = seq
        self.type = entry_type
        self.method = ""
        self.url = ""
        self.status = 0
        self.status_text = ""
        self.request_headers: dict = {}
        self.request_body = None
        self.response_headers: dict = {}
        self.response_body = None
        self.content_type = ""
        self.start_time = 0.0
        self.end_time = 0.0
        self.duration_ms = 0
        self.ws_messages: list = []
        self.failed = False

    @property
    def path(self) -> str:
        p = urllib.parse.urlparse(self.url).path or "/"
        return p if len(p) <= 60 else "…" + p[-57:]

    @property
    def domain(self) -> str:
        return urllib.parse.urlparse(self.url).netloc

    def to_dict(self) -> dict:
        d = {
            "seq": self.seq, "type": self.type, "method": self.method,
            "url": self.url, "status": self.status, "domain": self.domain,
            "duration_ms": self.duration_ms, "timestamp": self.start_time,
        }
        if self.request_body:
            d["request_body"] = self.request_body
        if self.response_body:
            d["response_body"] = self.response_body
        if self.request_headers:
            d["request_headers"] = self.request_headers
        if self.ws_messages:
            d["ws_messages"] = self.ws_messages
        return d

    def to_curl(self, include_auth: bool = True) -> str:
        parts = [f"curl -X {self.method}"]
        skip = {"host", "connection", "content-length", "accept-encoding"}
        for k, v in self.request_headers.items():
            if k.lower() in skip:
                continue
            if not include_auth and k.lower() in ("authorization", "cookie", "x-api-key"):
                continue
            parts.append(f"  -H '{k}: {v}'")
        if self.request_body:
            body = self.request_body if isinstance(self.request_body, str) else json.dumps(self.request_body)
            parts.append(f"  -d '{body}'")
        parts.append(f"  '{self.url}'")
        return " \\\n".join(parts)

    def to_python(self, func_name: str, include_auth: bool = True) -> str:
        parsed = urllib.parse.urlparse(self.url)
        params = urllib.parse.parse_qs(parsed.query) if parsed.query else {}
        skip_headers = {
            "host", "connection", "content-length", "accept-encoding",
            "user-agent", "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site",
            "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
            "accept", "origin", "referer", "content-type",
        }
        auth_keys = {"authorization", "x-api-key", "cookie", "x-telegram-init-data"}
        lines = []

        lines.append(f"def {func_name}(session=session):")
        lines.append(f'    """')
        lines.append(f'    {self.method} {parsed.path}')
        lines.append(f'    Status: {self.status} | Duration: {self.duration_ms}ms')
        lines.append(f'    """')

        # URL
        url_base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        lines.append(f"    url = f'{url_base}'")

        # Params
        if params:
            flat = {k: v[0] if len(v) == 1 else v for k, v in params.items()}
            lines.append("")
            lines.append("    params = {")
            for k, v in flat.items():
                lines.append(f"        '{k}': '{v}',  # ← edit")
            lines.append("    }")

        # Body
        body = None
        if self.request_body:
            try:
                body = json.loads(self.request_body)
            except (json.JSONDecodeError, TypeError):
                pass

        if body and isinstance(body, dict):
            lines.append("")
            lines.append("    payload = {")
            for k, v in body.items():
                vr = json.dumps(v, ensure_ascii=False)
                lines.append(f"        '{k}': {vr},  # ← edit")
            lines.append("    }")
        elif body and isinstance(body, list):
            lines.append(f"    payload = {json.dumps(body, ensure_ascii=False)}")
        elif self.request_body:
            lines.append(f"    data = {repr(self.request_body)}")

        # Extra headers
        extra = {k: v for k, v in self.request_headers.items()
                 if k.lower() not in skip_headers and (include_auth or k.lower() not in auth_keys)}
        if extra:
            lines.append("")
            lines.append("    headers = {")
            for k, v in extra.items():
                lines.append(f"        '{k}': '{v}',")
            lines.append("    }")

        # Request call
        method = self.method.lower()
        args = ["url"]
        if params:
            args.append("params=params")
        if extra:
            args.append("headers=headers")
        if body:
            args.append("json=payload" if isinstance(body, (dict, list)) else "data=data")
        elif self.request_body:
            args.append("data=data")

        lines.append("")
        lines.append(f"    resp = session.{method}(")
        for a in args:
            lines.append(f"        {a},")
        lines.append("    )")
        lines.append("    resp.raise_for_status()")
        lines.append("    return resp.json()")
        return "\n".join(lines)


class HARRecorder:
    """Captures XHR/Fetch/WebSocket traffic."""

    def __init__(self, scope: list[str] = None):
        self.scope = scope  # list of domains to filter, None = all
        self.entries: list[NetworkEntry] = []
        self._pending: dict[str, NetworkEntry] = {}
        self._ws_map: dict = {}
        self._seq = 0
        self._verbose = True
        self._auth_detected: dict[str, str] = {}

    def _next_seq(self) -> int:
        self._seq += 1
        return self._seq

    def _in_scope(self, url: str) -> bool:
        if not self.scope:
            return True
        domain = urllib.parse.urlparse(url).netloc
        return any(domain == s or domain.endswith(f".{s}") for s in self.scope)

    def attach(self, page, verbose: bool = True):
        self._verbose = verbose
        page.on("request", self._on_request)
        page.on("response", self._on_response)
        page.on("requestfailed", self._on_request_failed)
        page.on("websocket", self._on_websocket)
        scope_str = ", ".join(self.scope) if self.scope else "all domains"
        if verbose:
            print(f"[REC] Recording XHR/Fetch/WebSocket — scope: {scope_str}")

    def _on_request(self, request):
        rtype = request.resource_type
        if rtype not in ("xhr", "fetch"):
            return
        if not self._in_scope(request.url):
            return
        entry = NetworkEntry(self._next_seq(), rtype)
        entry.method = request.method
        entry.url = request.url
        entry.request_headers = dict(request.headers)
        entry.start_time = time.time()
        try:
            body = request.post_data
            if body:
                entry.request_body = body
        except Exception:
            pass
        self._pending[str(id(request))] = entry

    def _on_response(self, response):
        req_id = str(id(response.request))
        entry = self._pending.pop(req_id, None)
        if not entry:
            return
        entry.status = response.status
        entry.status_text = response.status_text
        entry.response_headers = dict(response.headers)
        entry.content_type = response.headers.get("content-type", "")
        entry.end_time = time.time()
        entry.duration_ms = round((entry.end_time - entry.start_time) * 1000)
        # Try body (async-safe: skip coroutine, only capture sync responses)
        try:
            result = response.body()
            if isinstance(result, bytes):
                text = result.decode("utf-8", errors="replace")
                try:
                    entry.response_body = json.loads(text)
                except (json.JSONDecodeError, TypeError):
                    if len(text) < 100_000:
                        entry.response_body = text
            # If it's a coroutine, just skip body capture
        except (TypeError, Exception):
            pass
        self.entries.append(entry)
        self._detect_auth(entry)
        if self._verbose:
            self._print_entry(entry)

    def _on_request_failed(self, request):
        req_id = str(id(request))
        entry = self._pending.pop(req_id, None)
        if not entry:
            return
        entry.status = 0
        entry.status_text = "FAILED"
        entry.failed = True
        entry.end_time = time.time()
        entry.duration_ms = round((entry.end_time - entry.start_time) * 1000)
        self.entries.append(entry)
        if self._verbose:
            self._print_entry(entry, failed=True)

    def _on_websocket(self, ws):
        entry = NetworkEntry(self._next_seq(), "websocket")
        entry.url = ws.url
        entry.method = "WS"
        entry.start_time = time.time()
        self.entries.append(entry)
        self._ws_map[ws.url] = entry
        if self._verbose:
            print(f"\033[36m  [WS OPEN]  {ws.url}\033[0m")

        def on_frame(*args):
            payload = args[0] if args else ""
            is_text = isinstance(payload, str) if len(args) == 1 else args[1]
            data = payload if is_text else payload.hex()
            entry.ws_messages.append({"dir": "recv", "data": data[:2000], "t": time.time()})
            if self._verbose:
                p = data[:200] if is_text else f"<binary {len(payload)}b>"
                print(f"\033[36m  [WS RECV]  {p}\033[0m")

        def on_sent(*args):
            payload = args[0] if args else ""
            is_text = isinstance(payload, str) if len(args) == 1 else args[1]
            data = payload if is_text else payload.hex()
            entry.ws_messages.append({"dir": "sent", "data": data[:2000], "t": time.time()})
            if self._verbose:
                p = data[:200] if is_text else f"<binary {len(payload)}b>"
                print(f"\033[34m  [WS SEND]  {p}\033[0m")

        def on_close():
            entry.end_time = time.time()
            entry.duration_ms = round((entry.end_time - entry.start_time) * 1000)
            if self._verbose:
                print(f"\033[33m  [WS CLOSE] {ws.url} ({len(entry.ws_messages)} msgs)\033[0m")

        ws.on("framereceived", on_frame)
        ws.on("framesent", on_sent)
        ws.on("close", on_close)

    def _detect_auth(self, entry: NetworkEntry):
        """Auto-detect auth tokens from request headers."""
        auth_patterns = {
            "authorization": r"^(Bearer|Basic|Token|JWT)\s+(.+)$",
            "x-api-key": r"^(.+)$",
            "x-auth-token": r"^(.+)$",
            "x-csrf-token": r"^(.+)$",
            "x-telegram-init-data": r"^(.+)$",
        }
        for k, v in entry.request_headers.items():
            kl = k.lower()
            if kl in auth_patterns:
                if kl not in self._auth_detected:
                    self._auth_detected[kl] = v

    def _print_entry(self, entry: NetworkEntry, failed: bool = False):
        colors = {"ok": "\033[92m", "warn": "\033[93m", "err": "\033[91m", "reset": "\033[0m", "dim": "\033[2m"}
        mc = {"GET": "\033[94m", "POST": "\033[93m", "PUT": "\033[95m",
              "PATCH": "\033[95m", "DELETE": "\033[91m", "WS": "\033[36m"}

        if failed:
            c, st = colors["err"], "FAIL"
        elif entry.status >= 400:
            c, st = colors["err"], str(entry.status)
        elif entry.status >= 300:
            c, st = colors["warn"], str(entry.status)
        else:
            c, st = colors["ok"], str(entry.status)

        body_hints = ""
        if entry.request_body:
            try:
                b = json.loads(entry.request_body)
                if isinstance(b, dict):
                    body_hints = f" → {list(b.keys())[:3]}"
            except (json.JSONDecodeError, TypeError):
                body_hints = f" → {entry.request_body[:40]}"

        resp_hints = ""
        if isinstance(entry.response_body, dict):
            resp_hints = f" ← {list(entry.response_body.keys())[:3]}"

        print(f"  {mc.get(entry.method, '')}{entry.method:7s}\033[0m "
              f"{c}{st:4s}\033[0m "
              f"{colors['dim']}{entry.duration_ms:5d}ms\033[0m "
              f"{entry.path}"
              f"{colors['dim']}{body_hints}{resp_hints}\033[0m")

    def get_auth(self) -> dict:
        return dict(self._auth_detected)

    def clear(self):
        self.entries.clear()
        self._pending.clear()
        self._ws_map.clear()
        self._auth_detected.clear()
        self._seq = 0

    # ── Export ──

    def to_har(self) -> dict:
        entries = []
        for e in self.entries:
            if e.type == "websocket":
                entries.append({
                    "startedDateTime": datetime.fromtimestamp(e.start_time, tz=timezone.utc).isoformat(),
                    "time": e.duration_ms,
                    "request": {"method": "WS", "url": e.url, "headers": [], "queryString": [],
                                "headersSize": -1, "bodySize": -1},
                    "response": {"status": 101, "statusText": "Switching Protocols", "headers": [],
                                 "content": {"size": len(e.ws_messages), "mimeType": "websocket",
                                             "text": json.dumps(e.ws_messages)},
                                 "headersSize": -1, "bodySize": -1},
                    "cache": {},
                    "timings": {"send": 0, "wait": e.duration_ms, "receive": 0},
                    "_ws": True, "_ws_messages": e.ws_messages,
                })
            else:
                parsed = urllib.parse.urlparse(e.url)
                qs = [{"name": k, "value": v[0]} for k, v in urllib.parse.parse_qs(parsed.query).items()]
                req_h = [{"name": k, "value": v} for k, v in e.request_headers.items()]
                resp_h = [{"name": k, "value": v} for k, v in e.response_headers.items()]
                resp_text = json.dumps(e.response_body, ensure_ascii=False) if isinstance(e.response_body, (dict, list)) else str(e.response_body or "")
                entries.append({
                    "startedDateTime": datetime.fromtimestamp(e.start_time, tz=timezone.utc).isoformat(),
                    "time": e.duration_ms,
                    "request": {"method": e.method, "url": e.url, "httpVersion": "h2",
                                "headers": req_h, "queryString": qs,
                                "headersSize": len(json.dumps(req_h)),
                                "bodySize": len(e.request_body) if e.request_body else 0},
                    "response": {"status": e.status, "statusText": e.status_text, "headers": resp_h,
                                 "content": {"size": len(resp_text), "mimeType": e.content_type,
                                             "text": resp_text[:100000]},
                                 "headersSize": len(json.dumps(resp_h)), "bodySize": len(resp_text)},
                    "cache": {},
                    "timings": {"send": 0, "wait": e.duration_ms, "receive": 0},
                })
        return {"log": {"version": "1.2", "creator": {"name": "web-trace", "version": "1.0"}, "entries": entries}}

    def save_har(self, path: str) -> str:
        Path(path).write_text(json.dumps(self.to_har(), indent=2, ensure_ascii=False))
        return path

    def to_python_script(self, impersonate: str = "chrome120") -> str:
        xhr = [e for e in self.entries if e.type in ("xhr", "fetch") and 200 <= e.status < 400]
        if not xhr:
            return "# No XHR/Fetch requests captured."

        # Group by domain
        by_domain: dict[str, list[NetworkEntry]] = {}
        for e in xhr:
            d = e.domain
            by_domain.setdefault(d, []).append(e)

        multi = len(by_domain) > 1
        lines = [
            "#!/usr/bin/env python3",
            '"""',
            f"Auto-generated from web-trace recording",
            f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Endpoints: {len(xhr)} | Domains: {len(by_domain)}",
            f"TLS fingerprint: {impersonate} (Chrome JA3/JA4)",
            "",
            "Uses curl_cffi for TLS fingerprint impersonation.",
            "Requests look like real Chrome at the network layer.",
            "",
            "Install: pip install curl_cffi",
            '"""',
            "",
            "from curl_cffi.requests import Session",
            "import json",
            "",
        ]

        auth_all = self.get_auth()
        func_names = []

        for didx, (domain, entries) in enumerate(by_domain.items()):
            var = f"s_{domain.replace('.', '_').replace('-', '_')}" if multi else "session"
            base = f"BASE_URL_{didx}" if multi else "BASE_URL"

            lines.append(f"# {'═' * 58}")
            lines.append(f"# {domain}")
            lines.append(f"# {'═' * 58}")
            lines.append(f"{base} = 'https://{domain}'")
            lines.append("")

            # Auth from this domain's entries
            domain_auth = {}
            for e in entries:
                for k, v in e.request_headers.items():
                    if k.lower() in ("authorization", "x-api-key", "cookie", "x-auth-token", "x-csrf-token"):
                        if k.lower() not in domain_auth:
                            domain_auth[k.lower()] = (k, v)

            if domain_auth:
                lines.append("# Auth tokens — auto-detected, replace when expired")
                for kl, (k, v) in domain_auth.items():
                    vn = k.upper().replace("-", "_")
                    if multi:
                        vn = f"{vn}_{didx}"
                    lines.append(f"{vn} = '{v}'")
                lines.append("")

            lines.append(f"{var} = Session(impersonate='{impersonate}')")
            if domain_auth:
                lines.append(f"{var}.headers.update({{")
                for kl, (k, v) in domain_auth.items():
                    vn = k.upper().replace("-", "_")
                    if multi:
                        vn = f"{vn}_{didx}"
                    lines.append(f"    '{k}': {vn},")
                lines.append("})")
            lines.append("")
            lines.append("")

            seen: dict[str, int] = {}
            for e in entries:
                raw = self._make_func_name(e.method, urllib.parse.urlparse(e.url).path)
                if raw in seen:
                    seen[raw] += 1
                    fn = f"{raw}_{seen[raw]}"
                else:
                    seen[raw] = 0
                    fn = raw
                if multi:
                    fn = f"{domain.split('.')[0]}_{fn}"
                func_names.append(fn)
                lines.append(e.to_python(fn))
                lines.append("")
                lines.append("")

        # Main
        lines.append(f"# {'═' * 58}")
        lines.append("# MAIN")
        lines.append(f"# {'═' * 58}")
        lines.append("")
        lines.append("if __name__ == '__main__':")
        lines.append("    results = {}")
        lines.append("")
        for fn in func_names:
            lines.append(f"    # results['{fn}'] = {fn}()")
            lines.append(f"    # print(json.dumps(results['{fn}'], indent=2))")
            lines.append("")
        lines.append("    pass")
        lines.append("")
        return "\n".join(lines)

    def to_curl_script(self) -> str:
        xhr = [e for e in self.entries if e.type in ("xhr", "fetch") and 200 <= e.status < 400]
        lines = [
            "#!/bin/bash",
            f"# web-trace — {len(xhr)} API calls",
            f"# Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "",
        ]
        for e in xhr:
            lines.append(f"# [{e.seq}] {e.method} {e.url}")
            lines.append(e.to_curl())
            lines.append("")
        return "\n".join(lines)

    def to_json(self) -> str:
        return json.dumps([e.to_dict() for e in self.entries], indent=2, ensure_ascii=False)

    def summary(self) -> str:
        by_type, by_status = {}, {}
        for e in self.entries:
            by_type[e.type] = by_type.get(e.type, 0) + 1
            by_status[e.status] = by_status.get(e.status, 0) + 1

        lines = [
            f"\n{'═' * 60}",
            f"  📊 Recording Summary",
            f"{'═' * 60}",
            f"  Total: {len(self.entries)} | Types: {by_type} | Status: {by_status}",
            f"{'─' * 60}",
        ]
        for e in self.entries:
            if e.type in ("xhr", "fetch"):
                icon = "📦" if e.request_body else "  "
                lines.append(f"  {icon} [{e.seq:3d}] {e.method:7s} {str(e.status):4s} {e.duration_ms:5d}ms  {e.path}")
            elif e.type == "websocket":
                lines.append(f"  🌐 [{e.seq:3d}] WS     OPEN  {len(e.ws_messages):4d}msgs  {e.url[:60]}")

        auth = self.get_auth()
        if auth:
            lines.append(f"{'─' * 60}")
            lines.append(f"  🔑 Detected auth:")
            for k, v in auth.items():
                preview = v[:60] + "..." if len(v) > 60 else v
                lines.append(f"    {k}: {preview}")

        lines.append(f"{'═' * 60}")
        return "\n".join(lines)

    @staticmethod
    def _make_func_name(method: str, path: str) -> str:
        clean = path.strip("/").replace("-", "_").replace(".", "_")
        for pfx in ("api_", "v1_", "v2_", "v3_"):
            if clean.startswith(pfx):
                clean = clean[len(pfx):]
                break
        clean = "__".join(clean.split("/"))
        # Remove non-alphanumeric chars except underscore
        clean = re.sub(r'[^a-zA-Z0-9_]', '_', clean)
        # Remove leading digits
        clean = clean.lstrip('0123456789')
        name = f"{method.lower()}_{clean}"
        return name or f"{method.lower()}_request"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Session Manager
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class SessionManager:
    """Save/load browser cookies + localStorage."""

    @staticmethod
    async def save(context, path: str):
        state = await context.storage_state()
        Path(path).write_text(json.dumps(state, indent=2))
        cookies = sum(len(c) for c in state.get("cookies", []))
        origins = len(state.get("origins", []))
        print(f"[SESS] Saved: {path} ({cookies} cookies, {origins} origins)")

    @staticmethod
    def load_args(path: str) -> dict:
        return {"storage_state": path}


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# WebTrace — Main Orchestrator
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class WebTrace:
    def __init__(self, **kw):
        self.kw = kw
        self.browser = None
        self.context = None
        self.page = None
        self.recorder: HARRecorder = None

    async def start(self):
        kw = self.kw
        scope = kw.get("scope")
        self.recorder = HARRecorder(scope=scope)

        pw = await async_playwright().start()
        headless = kw.get("headless", False)
        stealth = not kw.get("no_stealth", False)

        # Viewport
        vp_str = kw.get("viewport", "1280x800")
        w, h = vp_str.split("x")
        viewport = {"width": int(w), "height": int(h)}

        ua = kw.get("ua") or (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"
        )

        # ── Launch strategy: Real Chrome → bundled Chromium ──
        chrome = _find_chrome()
        chrome_proc = None
        cdp_url = None

        if chrome and stealth:
            port = _free_port()
            cdp_url = f"http://127.0.0.1:{port}"
            profile = "/tmp/web-trace-chrome" if os.name != "nt" else os.path.join(os.environ.get("TEMP", "C:\\tmp"), "web-trace-chrome")
            args = STEALTH_FLAGS + [
                f"--remote-debugging-port={port}",
                f"--window-size={viewport['width']},{viewport['height']}",
                f"--user-agent={ua}",
                f"--user-data-dir={profile}",
                # TLS/HTTP2 fingerprint matching
                "--disable-features=AcceptCHFrame,MediaRouter,DialMediaRouteProvider",
                "--enable-features=NetworkService,NetworkServiceInProcess",
                "--cipher-suite-blacklist=0x0033,0x0039,0x009C,0x009D",
            ]
            if headless:
                args.append("--headless=new")
            if kw.get("proxy"):
                args.append(f"--proxy-server={kw['proxy']}")

            print(f"\033[92m[CHROME] ✓ {chrome}\033[0m")
            print(f"[CHROME] CDP port: {port}")

            try:
                chrome_proc = subprocess.Popen(chrome, *([args] if isinstance(args, list) else [args]),
                                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception:
                chrome_proc = subprocess.Popen([chrome] + args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            for _ in range(20):
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=1):
                        break
                except (ConnectionRefusedError, socket.timeout):
                    await asyncio.sleep(0.5)
            else:
                chrome_proc.kill()
                chrome_proc = None
                cdp_url = None

            if cdp_url:
                try:
                    self.browser = await pw.chromium.connect_over_cdp(cdp_url)
                except Exception as e:
                    print(f"\033[93m[CHROME] CDP failed: {e}\033[0m")
                    chrome_proc.kill()
                    chrome_proc = None
                    cdp_url = None

        if not cdp_url:
            if not chrome:
                print(f"\033[93m[CHROME] No Chrome found — using bundled Chromium\033[0m")
            launch_args = [
                "--disable-blink-features=AutomationControlled",
                "--no-sandbox", "--disable-setuid-sandbox",
                "--disable-dev-shm-usage", "--disable-infobars",
            ]
            if kw.get("proxy"):
                launch_args.append(f"--proxy-server={kw['proxy']}")
            self.browser = await pw.chromium.launch(headless=headless, args=launch_args)

        ctx_args = {"viewport": viewport, "user_agent": ua, "locale": "en-US"}
        if kw.get("session"):
            ctx_args.update(SessionManager.load_args(kw["session"]))
            print(f"[SESS] Loaded: {kw['session']}")

        self.context = await self.browser.new_context(**ctx_args)
        self.page = await self.context.new_page()

        if stealth and not cdp_url:
            await self.page.add_init_script(_load_stealth_js())

        # Attach recorder
        self.recorder.attach(self.page)

        # Navigate
        url = kw.get("url", "about:blank")
        if not url.startswith("http"):
            url = f"https://{url}"
        print(f"[TRACE] → {url}")

        try:
            await self.page.goto(url, wait_until="domcontentloaded", timeout=kw.get("timeout", 60000))
        except Exception as e:
            print(f"[TRACE] Load: {e}")

        await self.page.wait_for_timeout(2000)
        return self

    async def screenshot(self, path="web_trace_screenshot.png"):
        await self.page.screenshot(path=path, full_page=True)
        print(f"[SS] {path}")

    async def interactive(self):
        print("""
┌─ web-trace REPL ─────────────────────────────────────────┐
│  info           Page info (text, buttons, links)          │
│  ss             Screenshot                                │
│  click <text>   Click element by text                     │
│  type <sel> <v> Type into selector                        │
│  scroll         Scroll down                               │
│  nav <url>      Navigate to URL                           │
│  requests       Show captured requests                    │
│  auth           Show detected auth headers/tokens         │
│  ws             Show WebSocket connections                │
│  har [file]     Save HAR                                  │
│  py [file]      Export Python script (with curl_cffi)     │
│  curl [file]    Export cURL commands                      │
│  json [file]    Export JSON dump                          │
│  replay <id>    Replay request with TLS impersonation     │
│  tls [profile]  Show/set TLS profile                      │
│  session [file] Save session (cookies + storage)          │
│  eval <js>      Execute JavaScript                        │
│  dump           Dump page HTML                            │
│  clear          Clear recorded requests                   │
│  quit           Exit                                      │
└───────────────────────────────────────────────────────────┘""")

        while True:
            try:
                cmd = await asyncio.get_event_loop().run_in_executor(
                    None, lambda: input("\n[trace] > ").strip()
                )
            except (EOFError, KeyboardInterrupt):
                break
            if not cmd:
                continue

            parts = cmd.split(" ", 2)
            action = parts[0].lower()

            if action == "quit":
                break

            elif action == "info":
                info = await self.page.evaluate("""() => {
                    const texts = [];
                    document.querySelectorAll('*').forEach(el => {
                        if (el.children.length === 0 && el.textContent.trim()) {
                            const s = getComputedStyle(el);
                            if (s.display !== 'none' && s.visibility !== 'hidden')
                                texts.push(el.textContent.trim());
                        }
                    });
                    const buttons = [];
                    document.querySelectorAll('button, [role="button"], .btn, a[class*="btn"]').forEach(b => {
                        buttons.push({text: b.textContent.trim().substring(0, 80), vis: b.offsetParent !== null});
                    });
                    const links = [];
                    document.querySelectorAll('a[href]').forEach(a => {
                        links.push({text: a.textContent.trim().substring(0, 60), href: a.href});
                    });
                    return {title: document.title, texts, buttons, links};
                }""")
                print(f"\n📄 {info['title']}")
                for t in info['texts'][:30]:
                    print(f"  • {t[:80]}")
                print(f"🔘 Buttons ({len(info['buttons'])}):")
                for b in info['buttons'][:20]:
                    print(f"  [{'✓' if b['vis'] else '✗'}] {b['text']}")
                print(f"🔗 Links ({len(info['links'])}):")
                for l in info['links'][:20]:
                    print(f"  • {l['text']} → {l['href'][:80]}")

            elif action == "ss":
                await self.screenshot()

            elif action == "click" and len(parts) > 1:
                text = parts[1]
                try:
                    await self.page.get_by_role("button", name=text, exact=False).click()
                    print(f"  Clicked button: '{text}'")
                except Exception:
                    try:
                        await self.page.click(f"text={text}")
                        print(f"  Clicked text: '{text}'")
                    except Exception:
                        print(f"  Not found: '{text}'")
                await self.page.wait_for_timeout(1500)

            elif action == "type" and len(parts) >= 3:
                sel, val = parts[1], parts[2]
                try:
                    await self.page.fill(sel, val)
                    print(f"  Typed into '{sel}'")
                except Exception as e:
                    print(f"  Error: {e}")

            elif action == "scroll":
                await self.page.mouse.wheel(0, 500)
                await self.page.wait_for_timeout(800)

            elif action == "nav" and len(parts) > 1:
                url = parts[1]
                if not url.startswith("http"):
                    url = f"https://{url}"
                try:
                    await self.page.goto(url, wait_until="domcontentloaded", timeout=30000)
                    print(f"  → {url}")
                except Exception as e:
                    print(f"  Error: {e}")

            elif action == "requests":
                print(self.recorder.summary())

            elif action == "auth":
                auth = self.recorder.get_auth()
                if not auth:
                    print("  No auth tokens detected yet.")
                else:
                    print(f"\n  🔑 Detected auth ({len(auth)}):")
                    for k, v in auth.items():
                        preview = v[:80] + "..." if len(v) > 80 else v
                        print(f"    {k}: {preview}")

            elif action == "ws":
                ws = [e for e in self.recorder.entries if e.type == "websocket"]
                if not ws:
                    print("  No WebSocket connections.")
                else:
                    for e in ws:
                        print(f"  🌐 {e.url} — {len(e.ws_messages)} messages, {e.duration_ms}ms")

            elif action == "har":
                f = parts[1] if len(parts) > 1 else kw.get("har", "web_traffic.har")
                self.recorder.save_har(f)
                print(f"  💾 HAR: {f}")

            elif action == "py":
                f = parts[1] if len(parts) > 1 else "web_trace_exploit.py"
                profile = self.kw.get("impersonate", "chrome120")
                Path(f).write_text(self.recorder.to_python_script(impersonate=profile))
                print(f"  💾 Python: {f} (TLS: {profile})")

            elif action == "curl":
                f = parts[1] if len(parts) > 1 else "web_trace_curls.sh"
                Path(f).write_text(self.recorder.to_curl_script())
                print(f"  💾 cURL: {f}")

            elif action == "json":
                f = parts[1] if len(parts) > 1 else "web_trace_dump.json"
                Path(f).write_text(self.recorder.to_json())
                print(f"  💾 JSON: {f}")

            elif action == "session":
                f = parts[1] if len(parts) > 1 else "session.json"
                await SessionManager.save(self.context, f)

            elif action == "eval" and len(parts) > 1:
                js = cmd.split(" ", 1)[1]
                try:
                    r = await self.page.evaluate(js)
                    print(f"  → {r}")
                except Exception as e:
                    print(f"  Error: {e}")

            elif action == "dump":
                html = await self.page.content()
                print(html[:8000])

            elif action == "clear":
                self.recorder.clear()
                print("  Cleared.")

            elif action == "replay" and len(parts) > 1:
                if not HAS_CURL_CFFI:
                    print("  ⚠️  curl_cffi not installed. pip install curl_cffi")
                    continue
                try:
                    seq = int(parts[1])
                except ValueError:
                    print("  Usage: replay <seq_number>  (e.g., replay 3)")
                    continue
                target = None
                for e in self.recorder.entries:
                    if e.seq == seq and e.type in ("xhr", "fetch"):
                        target = e
                        break
                if not target:
                    print(f"  Request #{seq} not found.")
                    continue

                profile = self.kw.get("impersonate", "chrome120")
                print(f"\n  🔁 Replaying [{seq}] {target.method} {target.path}")
                print(f"  TLS profile: {profile}")
                print(f"  Original status: {target.status}")

                # Allow user to modify headers
                auth = self.recorder.get_auth()
                headers = {}
                for k, v in target.request_headers.items():
                    kl = k.lower()
                    if kl in ("authorization", "x-api-key", "cookie", "x-auth-token", "x-csrf-token"):
                        headers[k] = v
                    elif kl not in ("host", "connection", "content-length", "accept-encoding",
                                     "user-agent", "sec-fetch-dest", "sec-fetch-mode",
                                     "sec-fetch-site", "sec-ch-ua", "sec-ch-ua-mobile",
                                     "sec-ch-ua-platform"):
                        headers[k] = v

                body = target.request_body
                if body:
                    print(f"  Body: {body[:200]}")
                    modify = input("  Modify body? (y/N): ").strip().lower()
                    if modify == "y":
                        body = input("  New body: ").strip() or body

                try:
                    client = TLSClient(impersonate=profile, headers=headers)
                    resp = client.request(target.method, target.url, data=body)
                    print(f"\n  ✅ Response: {resp.status_code}")
                    print(f"  Headers: {dict(list(resp.headers.items())[:5])}")
                    try:
                        print(f"  Body: {resp.text[:500]}")
                    except Exception:
                        print(f"  Body: <binary {len(resp.content)} bytes>")
                    client.close()
                except Exception as e:
                    print(f"  ❌ Error: {e}")

            elif action == "tls":
                profile = self.kw.get("impersonate", "chrome120")
                if len(parts) > 1:
                    new_profile = parts[1]
                    if HAS_CURL_CFFI and new_profile in ALL_PROFILES:
                        self.kw["impersonate"] = new_profile
                        print(f"  TLS profile: {new_profile}")
                    else:
                        print(f"  Unknown profile: {new_profile}")
                        if HAS_CURL_CFFI:
                            print(f"  Available: {', '.join(ALL_PROFILES.keys())}")
                        else:
                            print("  ⚠️  curl_cffi not installed.")
                else:
                    print(f"  Current: {profile}")
                    if HAS_CURL_CFFI:
                        print(f"  Available: {', '.join(ALL_PROFILES.keys())}")

            else:
                print(f"  Unknown: {cmd}")

    async def close(self):
        har_path = self.kw.get("har")
        if har_path:
            self.recorder.save_har(har_path)
            print(f"[HAR] Saved: {har_path}")

        export = self.kw.get("export")
        if export:
            profile = self.kw.get("impersonate", "chrome120")
            if export == "har":
                fname = har_path or "web_traffic.har"
                self.recorder.save_har(fname)
            elif export == "py":
                fname = "web_trace_exploit.py"
                Path(fname).write_text(self.recorder.to_python_script(impersonate=profile))
            elif export == "curl":
                fname = "web_trace_curls.sh"
                Path(fname).write_text(self.recorder.to_curl_script())
            elif export == "json":
                fname = "web_trace_dump.json"
                Path(fname).write_text(self.recorder.to_json())
            print(f"[EXPORT] {export}: {fname}")

        save_sess = self.kw.get("save_session")
        if save_sess:
            await SessionManager.save(self.context, save_sess)

        if self.browser:
            try:
                await self.browser.close()
            except Exception:
                pass
        # Kill Chrome process if we launched one
        if hasattr(self, '_chrome_proc') and self._chrome_proc:
            try:
                self._chrome_proc.terminate()
                self._chrome_proc.wait(timeout=3)
            except Exception:
                try:
                    self._chrome_proc.kill()
                except Exception:
                    pass
        print("[TRACE] Done.")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# CLI
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def main():
    p = argparse.ArgumentParser(
        description="web-trace — HAR recorder for bug bounty hunting",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 web_trace.py https://target.com
  python3 web_trace.py https://target.com --scope api.target.com
  python3 web_trace.py https://target.com --headless --ss --har out.har
  python3 web_trace.py https://target.com --export py --session authed.json
  python3 web_trace.py https://target.com --save-session authed.json
        """,
    )
    p.add_argument("url", help="Target URL")
    p.add_argument("--scope", action="append", help="Record only these domains (repeatable)")
    p.add_argument("--headless", action="store_true", help="No GUI")
    p.add_argument("--ss", action="store_true", help="Screenshot + exit")
    p.add_argument("--delay", type=int, default=5, help="Seconds to wait before exit (with --ss)")
    p.add_argument("--har", metavar="FILE", help="Save HAR to file")
    p.add_argument("--export", choices=["har", "py", "curl", "json"], help="Export format on exit")
    p.add_argument("--session", metavar="FILE", help="Load session (cookies + storage)")
    p.add_argument("--save-session", metavar="FILE", help="Save session on exit")
    p.add_argument("--ua", help="Custom User-Agent")
    p.add_argument("--viewport", default="1280x800", help="Viewport WxH (default: 1280x800)")
    p.add_argument("--no-stealth", action="store_true", help="Disable stealth patches")
    p.add_argument("--proxy", help="Proxy (socks5://host:port or http://host:port)")
    p.add_argument("--timeout", type=int, default=60000, help="Navigation timeout (ms)")
    p.add_argument("--impersonate", default="chrome120",
                   help="TLS fingerprint profile for replay (default: chrome120). "
                        "Options: chrome120, chrome119, chrome116, safari17_0, firefox120, etc.")
    args = p.parse_args()

    trace = WebTrace(
        url=args.url, scope=args.scope, headless=args.headless,
        har=args.har, export=args.export, session=args.session,
        save_session=args.save_session, ua=args.ua, viewport=args.viewport,
        no_stealth=args.no_stealth, proxy=args.proxy, timeout=args.timeout,
    )

    async def run():
        await trace.start()
        if args.ss:
            await asyncio.sleep(args.delay)
            await trace.screenshot()
            print(trace.recorder.summary())
            await trace.close()
            return
        await trace.interactive()
        await trace.close()

    asyncio.run(run())


if __name__ == "__main__":
    # Suppress asyncio cleanup warnings from Chrome subprocess
    import warnings
    warnings.filterwarnings("ignore", message=".*Event loop is closed.*")
    warnings.filterwarnings("ignore", message=".*was never awaited.*")
    main()
