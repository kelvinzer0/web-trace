#!/usr/bin/env python3
"""
TLS Fingerprint Impersonation Module for web-trace.

Uses curl_cffi to make HTTP requests with Chrome's exact TLS fingerprint (JA3/JA4),
HTTP/2 SETTINGS frame, and header ordering — indistinguishable from real Chrome
at the network layer.

curl-impersonate profiles available:
    chrome120, chrome119, chrome116, chrome110, chrome107, chrome104, chrome101,
    chrome99, chrome96, chrome91, chrome87, chrome83, chrome72,
    safari17_0, safari16_0, safari15_5, safari15_3,
    firefox120, firefox117, firefox109, firefox102, firefox91,
    edge101, opera90
"""

from curl_cffi.requests import Session as CurlSession


# ── Chrome TLS profiles (most common for bug bounty) ──

CHROME_PROFILES = {
    "chrome120": "chrome120",
    "chrome119": "chrome119",
    "chrome116": "chrome116",
    "chrome110": "chrome110",
    "chrome107": "chrome107",
    "chrome104": "chrome104",
    "chrome101": "chrome101",
    "chrome99":  "chrome99",
    "chrome96":  "chrome96",
    "chrome91":  "chrome91",
    "chrome87":  "chrome87",
    "chrome83":  "chrome83",
}

SAFARI_PROFILES = {
    "safari17_0": "safari17_0",
    "safari16_0": "safari16_0",
    "safari15_5": "safari15_5",
    "safari15_3": "safari15_3",
}

FIREFOX_PROFILES = {
    "firefox120": "firefox120",
    "firefox117": "firefox117",
    "firefox109": "firefox109",
    "firefox102": "firefox102",
    "firefox91":  "firefox91",
}

ALL_PROFILES = {**CHROME_PROFILES, **SAFARI_PROFILES, **FIREFOX_PROFILES}


class TLSClient:
    """
    HTTP client with TLS fingerprint impersonation.

    Usage:
        client = TLSClient(impersonate="chrome120")
        resp = client.get("https://api.target.com/user")
        resp = client.post("https://api.target.com/login", json={"user": "admin"})
    """

    def __init__(self, impersonate: str = "chrome120", proxy: str = None,
                 headers: dict = None, cookies: dict = None):
        """
        Args:
            impersonate: Browser profile to impersonate (e.g., "chrome120", "safari17_0")
            proxy: Proxy URL (socks5://host:port or http://host:port)
            headers: Default headers for all requests
            cookies: Default cookies
        """
        self.impersonate = impersonate
        self._session = CurlSession(impersonate=impersonate)

        if proxy:
            self._session.proxies = {"http": proxy, "https": proxy}

        if headers:
            self._session.headers.update(headers)

        if cookies:
            for k, v in cookies.items():
                self._session.cookies.set(k, v)

    def get(self, url: str, **kwargs):
        return self._session.get(url, **kwargs)

    def post(self, url: str, **kwargs):
        return self._session.post(url, **kwargs)

    def put(self, url: str, **kwargs):
        return self._session.put(url, **kwargs)

    def patch(self, url: str, **kwargs):
        return self._session.patch(url, **kwargs)

    def delete(self, url: str, **kwargs):
        return self._session.delete(url, **kwargs)

    def request(self, method: str, url: str, **kwargs):
        return self._session.request(method, url, **kwargs)

    @property
    def cookies(self):
        return self._session.cookies

    @property
    def headers(self):
        return self._session.headers

    def close(self):
        self._session.close()


def create_client_from_auth(auth_headers: dict, impersonate: str = "chrome120",
                             proxy: str = None) -> TLSClient:
    """
    Create a TLSClient from auto-detected auth headers.

    Args:
        auth_headers: Dict of auth headers from HARRecorder.get_auth()
        impersonate: Browser profile to impersonate
        proxy: Optional proxy

    Returns:
        TLSClient ready to use
    """
    return TLSClient(impersonate=impersonate, proxy=proxy, headers=auth_headers)


def profile_info(name: str) -> str:
    """Get info about a TLS profile."""
    info = {
        "chrome120": "Chrome 120 — Windows 10, TLS 1.3, h2, most common",
        "chrome119": "Chrome 119 — Windows 10, TLS 1.3, h2",
        "chrome116": "Chrome 116 — Windows 10, TLS 1.3, h2",
        "safari17_0": "Safari 17.0 — macOS Sonoma, TLS 1.3, h2",
        "safari15_5": "Safari 15.5 — macOS Monterey, TLS 1.3, h2",
        "firefox120": "Firefox 120 — Windows 10, TLS 1.3, h2",
        "firefox102": "Firefox 102 ESR — Windows 10, TLS 1.3, h2",
    }
    return info.get(name, f"Profile: {name}")
