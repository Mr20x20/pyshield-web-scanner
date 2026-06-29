"""
discovery.py — PyShield Web Security Scanner
Endpoint discovery — finds pages and paths on the target
before the main checks run.

What we discover:
  1. robots.txt    — site owners list paths they want hidden from search engines
                     attackers read this to find admin panels and sensitive dirs
  2. sitemap.xml   — lists all public URLs on the site
  3. Target metadata — title, server, redirect chain, base URL

Why this matters:
  robots.txt often contains entries like:
    Disallow: /admin/
    Disallow: /backup/
    Disallow: /.env
  These are exactly the paths we should check in exposed_files.py.
  Discovery feeds additional paths into the scanner dynamically.
"""

import logging
import re
import urllib.parse

from http_client import HTTPClient, Response

logger = logging.getLogger("webscanner.discovery")


# ── Public API ────────────────────────────────────────────────────────────────
def run(client: HTTPClient) -> dict:
    """
    Run all discovery steps against the target.

    Returns:
    {
        "base_url":      "https://example.com",
        "title":         "Example Domain",
        "server":        "nginx/1.18.0",
        "redirects":     ["http://example.com → https://example.com"],
        "robots_paths":  ["/admin/", "/backup/"],
        "sitemap_urls":  ["https://example.com/about"],
        "technologies":  ["WordPress", "PHP"],
    }
    """
    logger.info("Starting endpoint discovery...")

    result = {
        "base_url":     client.base_url,
        "title":        "",
        "server":       "",
        "redirects":    [],
        "robots_paths": [],
        "sitemap_urls": [],
        "technologies": [],
    }

    # ── Step 1: Fetch root page ───────────────────────────────────────────────
    root = client.get("/")
    if root.ok:
        result["title"]  = _extract_title(root.body)
        result["server"] = root.header("server")

        # Detect redirect chain
        if root.redirected and root.final_url != root.url:
            result["redirects"].append(
                f"{root.url} → {root.final_url}"
            )

        # Detect technologies from headers and body
        result["technologies"] = _detect_technologies(root)
        logger.info(
            "Root page: status=%d title='%s' server='%s'",
            root.status_code,
            result["title"][:50],
            result["server"],
        )

    # ── Step 2: Parse robots.txt ──────────────────────────────────────────────
    robots = client.get("/robots.txt")
    if robots.ok and robots.is_success:
        result["robots_paths"] = _parse_robots(robots.body)
        logger.info(
            "robots.txt: found %d disallowed paths",
            len(result["robots_paths"])
        )

    # ── Step 3: Parse sitemap.xml ─────────────────────────────────────────────
    sitemap = client.get("/sitemap.xml")
    if sitemap.ok and sitemap.is_success:
        result["sitemap_urls"] = _parse_sitemap(sitemap.body)
        logger.info(
            "sitemap.xml: found %d URLs",
            len(result["sitemap_urls"])
        )

    logger.info(
        "Discovery complete: %d robots paths, %d sitemap URLs, "
        "%d technologies detected",
        len(result["robots_paths"]),
        len(result["sitemap_urls"]),
        len(result["technologies"]),
    )

    return result


# ── Parsers ───────────────────────────────────────────────────────────────────
def _parse_robots(body: str) -> list[str]:
    """
    Extract Disallow paths from robots.txt.

    robots.txt format:
      User-agent: *
      Disallow: /admin/
      Disallow: /private/
      Allow: /public/

    We collect Disallow paths — these are what site owners
    explicitly want to hide, making them interesting targets.
    """
    paths = []
    for line in body.split("\n"):
        line = line.strip()
        if line.lower().startswith("disallow:"):
            path = line.split(":", 1)[1].strip()
            if path and path != "/":
                paths.append(path)
    return list(set(paths))   # deduplicate


def _parse_sitemap(body: str) -> list[str]:
    """
    Extract URLs from sitemap.xml.
    Sitemaps use <loc> tags to list URLs.
    We take up to 20 URLs — enough for context without overloading.
    """
    pattern = re.compile(r"<loc>\s*(https?://[^\s<]+)\s*</loc>", re.I)
    urls    = pattern.findall(body)
    return urls[:20]


def _extract_title(body: str) -> str:
    """Extract the <title> tag content from HTML."""
    match = re.search(r"<title[^>]*>([^<]+)</title>", body, re.I)
    if match:
        return match.group(1).strip()[:100]
    return ""


def _detect_technologies(response: Response) -> list[str]:
    """
    Detect technologies from response headers and body.
    This gives context to the scan — knowing it's WordPress
    means we look harder at /wp-admin/ and /wp-config.php.
    """
    techs  = []
    body   = response.body.lower()
    server = response.header("server").lower()
    powered = response.header("x-powered-by").lower()

    # Server header
    if "nginx"   in server: techs.append("nginx")
    if "apache"  in server: techs.append("Apache")
    if "iis"     in server: techs.append("Microsoft IIS")
    if "litespeed" in server: techs.append("LiteSpeed")

    # X-Powered-By
    if "php"     in powered: techs.append("PHP")
    if "asp.net" in powered: techs.append("ASP.NET")

    # Body signatures
    if "wp-content" in body or "wp-includes" in body:
        techs.append("WordPress")
    if "joomla"  in body: techs.append("Joomla")
    if "drupal"  in body: techs.append("Drupal")
    if "laravel" in body: techs.append("Laravel")
    if "django"  in body: techs.append("Django")
    if "react"   in body: techs.append("React")
    if "angular" in body: techs.append("Angular")
    if "vue"     in body: techs.append("Vue.js")

    # Cookie-based detection
    cookies = response.header("set-cookie").lower()
    if "phpsessid"  in cookies: techs.append("PHP Sessions")
    if "laravel_session" in cookies: techs.append("Laravel")
    if "csrftoken"  in cookies: techs.append("Django")

    return list(set(techs))
