"""
checks/directory.py — PyShield Web Security Scanner
Detects directory listing enabled on the web server.

Directory listing is when a web server shows the contents of a folder
instead of returning 403 or a custom page — like a file browser in the browser.

Why it's dangerous:
  If /uploads/ has directory listing enabled, an attacker can see:
  - All uploaded files (including private ones)
  - Backup files, config files, sensitive documents
  - File names that reveal internal structure

Example of what directory listing looks like in a browser:
  Index of /uploads/
  [ICO]  Name          Last modified    Size
  [   ]  backup.sql    2024-01-15       2.3M   ← database dump exposed!
  [   ]  .env.bak      2024-01-10       512    ← environment file exposed!
"""

import logging

from config import DIRECTORY_LISTING_SIGNATURES, DIRECTORY_PATHS
from http_client import HTTPClient

logger = logging.getLogger("webscanner.checks.directory")


def run(client: HTTPClient) -> list[dict]:
    findings = []
    logger.info(
        "Checking %d paths for directory listing...",
        len(DIRECTORY_PATHS)
    )

    from concurrent.futures import ThreadPoolExecutor, as_completed

    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {
            executor.submit(_check_path, client, path): path
            for path in DIRECTORY_PATHS
        }
        for future in as_completed(futures):
            result = future.result()
            if result:
                findings.append(result)
                logger.warning(
                    "Directory listing ENABLED: %s",
                    result["path"]
                )

    logger.info(
        "Directory listing checks complete: %d finding(s)",
        len(findings)
    )
    return findings


# ── Internal ──────────────────────────────────────────────────────────────────
def _check_path(client: HTTPClient, path: str) -> dict | None:
    """
    Check a single path for directory listing.
    Returns a finding dict or None.
    """
    response = client.get(path)

    if not response.ok or response.status_code != 200:
        return None

    # Check response body for directory listing signatures
    body     = response.body
    detected = _detect_listing(body)

    if not detected:
        return None

    # Try to extract some filenames as evidence
    evidence = _extract_file_list(body)

    return {
        "check":       "directory_listing",
        "path":        path,
        "description": f"Directory listing enabled on {path}",
        "severity":    _get_severity(path),
        "evidence":    evidence,
        "recommendation": (
            "Disable directory listing in your web server configuration. "
            "For Apache: add 'Options -Indexes' to .htaccess or httpd.conf. "
            "For nginx: remove 'autoindex on' from the location block."
        ),
    }


def _detect_listing(body: str) -> bool:
    """
    Return True if the response body contains directory listing signatures.
    """
    for signature in DIRECTORY_LISTING_SIGNATURES:
        if signature in body:
            return True
    return False


def _extract_file_list(body: str) -> str:
    """
    Extract up to 5 filenames from directory listing HTML.
    Used as evidence in the finding.
    """
    import re

    # Match href links that look like files (not parent directory links)
    pattern = re.compile(
        r'href=["\']([^"\'?#]+)["\']',
        re.IGNORECASE
    )

    files = []
    for match in pattern.finditer(body):
        name = match.group(1)
        # Skip navigation links and icons
        if name in ("../", "/", "?", "#"):
            continue
        if name.startswith("http"):
            continue
        if name.startswith("?"):
            continue
        files.append(name)
        if len(files) >= 5:
            break

    if files:
        return f"Files visible: {', '.join(files)}"
    return "Directory listing confirmed (no files extracted)"


def _get_severity(path: str) -> str:
    """
    Assign severity based on which directory has listing enabled.
    Sensitive directories are more critical than static asset dirs.
    """
    critical_dirs = ["/backup/", "/logs/", "/data/", "/tmp/", "/temp/"]
    high_dirs     = ["/uploads/", "/files/", "/media/"]

    if any(path.startswith(d) for d in critical_dirs):
        return "CRITICAL"
    if any(path.startswith(d) for d in high_dirs):
        return "HIGH"
    return "MEDIUM"
