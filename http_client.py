"""
http_client.py — PyShield Web Security Scanner
Central HTTP client. All other modules use this for requests.

Why centralize HTTP?
  If every module creates its own requests.Session(), we get:
  - Inconsistent headers across checks
  - No shared connection pooling
  - Timeout/retry logic duplicated everywhere

  One client = consistent behavior + single place to change settings.
"""

import logging
import urllib.parse
from dataclasses import dataclass

import requests
import urllib3

from config import REQUEST_TIMEOUT, MAX_REDIRECTS, USER_AGENT, VERIFY_SSL

# Suppress SSL warnings — we handle SSL ourselves in tls.py
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger("webscanner.http_client")


# ── Response wrapper ──────────────────────────────────────────────────────────
@dataclass
class Response:
    """
    Clean wrapper around requests.Response.
    Gives us only what we need — no raw requests internals leaking
    into check modules.
    """
    url:         str
    status_code: int
    headers:     dict        # lowercase keys for easy lookup
    body:        str
    redirected:  bool        # True if we followed any redirects
    final_url:   str         # URL after redirects
    error:       str = ""    # non-empty if request failed

    @property
    def ok(self) -> bool:
        """True if request succeeded (no network error)."""
        return not self.error

    @property
    def is_success(self) -> bool:
        """True if HTTP 2xx response."""
        return 200 <= self.status_code < 300

    @property
    def is_redirect(self) -> bool:
        return 300 <= self.status_code < 400

    @property
    def is_forbidden(self) -> bool:
        return self.status_code in (401, 403)

    @property
    def is_not_found(self) -> bool:
        return self.status_code == 404

    def header(self, name: str) -> str:
        """Case-insensitive header lookup."""
        return self.headers.get(name.lower(), "")


# ── HTTP Client ───────────────────────────────────────────────────────────────
class HTTPClient:
    """
    Wrapper around requests.Session with consistent settings.
    One instance per scan — shared across all check modules.
    """

    def __init__(self, base_url: str):
        """
        Args:
            base_url: target URL e.g. "https://example.com"
                      Normalized to include scheme, no trailing slash.
        """
        self.base_url = _normalize_url(base_url)
        self._session = self._build_session()
        logger.info("HTTP client initialized for %s", self.base_url)

    def get(self, path: str = "/",
            follow_redirects: bool = True) -> Response:
        """
        GET request to base_url + path.

        Args:
            path            : URL path e.g. "/.env", "/admin/"
            follow_redirects: if False, we capture the redirect response
                              itself (useful for detecting open redirects)
        """
        url = self._build_url(path)

        try:
            r = self._session.get(
                url,
                allow_redirects=follow_redirects,
                timeout=REQUEST_TIMEOUT,
            )

            return Response(
                url         = url,
                status_code = r.status_code,
                headers     = {k.lower(): v for k, v in r.headers.items()},
                body        = r.text[:50000],   # cap body at 50KB
                redirected  = len(r.history) > 0,
                final_url   = r.url,
            )

        except requests.exceptions.SSLError as e:
            logger.debug("SSL error for %s: %s", url, e)
            return _error_response(url, f"SSL error: {e}")

        except requests.exceptions.ConnectionError as e:
            logger.debug("Connection error for %s: %s", url, e)
            return _error_response(url, f"Connection error: {e}")

        except requests.exceptions.Timeout:
            logger.debug("Timeout for %s", url)
            return _error_response(url, "Request timed out")

        except Exception as e:
            logger.debug("Unexpected error for %s: %s", url, e)
            return _error_response(url, str(e))

    def get_headers_only(self, path: str = "/") -> Response:
        """
        HEAD request — fetches only headers, no body.
        Faster for header checks where we don't need the response body.
        Falls back to GET if HEAD is not supported (405).
        """
        url = self._build_url(path)

        try:
            r = self._session.head(
                url,
                allow_redirects=True,
                timeout=REQUEST_TIMEOUT,
            )

            # Some servers don't support HEAD — fall back to GET
            if r.status_code == 405:
                return self.get(path)

            return Response(
                url         = url,
                status_code = r.status_code,
                headers     = {k.lower(): v for k, v in r.headers.items()},
                body        = "",
                redirected  = len(r.history) > 0,
                final_url   = r.url,
            )

        except Exception as e:
            return _error_response(url, str(e))

    def _build_url(self, path: str) -> str:
        """Combine base URL with path safely."""
        if path.startswith("http://") or path.startswith("https://"):
            return path
        path = "/" + path.lstrip("/")
        return self.base_url + path

    def _build_session(self) -> requests.Session:
        """Build a configured requests.Session."""
        session = requests.Session()
        session.headers.update({"User-Agent": USER_AGENT})
        session.verify  = VERIFY_SSL
        session.max_redirects = MAX_REDIRECTS
        return session

    def close(self) -> None:
        self._session.close()


# ── Helpers ───────────────────────────────────────────────────────────────────
def _normalize_url(url: str) -> str:
    """
    Normalize a URL for consistent use across the scanner.

    Examples:
      "example.com"          → "http://example.com"
      "https://example.com/" → "https://example.com"
      "http://EXAMPLE.COM"   → "http://example.com"
    """
    url = url.strip()

    # Add scheme if missing
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    # Parse and rebuild cleanly
    parsed = urllib.parse.urlparse(url)
    scheme  = parsed.scheme.lower()
    host    = parsed.netloc.lower().rstrip("/")
    path    = parsed.path.rstrip("/")

    return f"{scheme}://{host}{path}"


def _error_response(url: str, error: str) -> Response:
    """Build a Response object representing a failed request."""
    return Response(
        url         = url,
        status_code = 0,
        headers     = {},
        body        = "",
        redirected  = False,
        final_url   = url,
        error       = error,
    )
