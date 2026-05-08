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
    "chrome99":  "chrome99",
    "chrome100": "chrome100",
    "chrome101": "chrome101",
    "chrome104": "chrome104",
    "chrome107": "chrome107",
    "chrome110": "chrome110",
    "chrome116": "chrome116",
    "chrome119": "chrome119",
    "chrome120": "chrome120",
    "chrome123": "chrome123",
    "chrome124": "chrome124",
    "chrome131": "chrome131",
}

SAFARI_PROFILES = {
    "safari15_3": "safari15_3",
    "safari15_5": "safari15_5",
    "safari17_0": "safari17_0",
    "safari18_0": "safari18_0",
}

FIREFOX_PROFILES = {
    "firefox133": "firefox133",
}

EDGE_PROFILES = {
    "edge99":  "edge99",
    "edge101": "edge101",
}

ALL_PROFILES = {**CHROME_PROFILES, **SAFARI_PROFILES, **FIREFOX_PROFILES, **EDGE_PROFILES}


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
        "chrome120": "Chrome 120 — Win10, TLS 1.3, h2, most common",
        "chrome119": "Chrome 119 — Win10, TLS 1.3, h2",
        "chrome116": "Chrome 116 — Win10, TLS 1.3, h2",
        "chrome131": "Chrome 131 — Win10, TLS 1.3, h2, latest",
        "safari17_0": "Safari 17.0 — macOS Sonoma, TLS 1.3, h2",
        "safari18_0": "Safari 18.0 — macOS Sequoia, TLS 1.3, h2, latest",
        "safari15_5": "Safari 15.5 — macOS Monterey, TLS 1.3, h2",
        "firefox133": "Firefox 133 — Win10, TLS 1.3, h2",
        "edge99": "Edge 99 — Win10, TLS 1.3, h2",
        "edge101": "Edge 101 — Win10, TLS 1.3, h2",
    }
    return info.get(name, f"Profile: {name}")
