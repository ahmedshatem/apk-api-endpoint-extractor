#!/usr/bin/env python3
"""Extract likely API endpoints from an Android APK - Enhanced Filtering.

This version filters out common false positives:
- Binary/media files (.bin, .jpg, .mp4, etc.)
- External bug trackers and docs
- CDN and asset URLs
- Known false patterns

Output format:
    POST https://api.example.com/login
    GET https://api.example.com/v1/users
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from collections import OrderedDict
from urllib.parse import urlparse

URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
PATH_RE = re.compile(
    r"(?:/|https?://)[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+(?:/api|/v\d+|/graphql|/oauth|/auth|/login|/signup|/register|/users|/orders|/payments|/profile|/search|/mobile|/graphql)[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]*",
    re.IGNORECASE,
)

# Useful for method guessing from surrounding context in the decompiled source.
METHOD_HINTS = {
    "get": "GET",
    "post": "POST",
    "put": "PUT",
    "patch": "PATCH",
    "delete": "DELETE",
    "update": "PUT",
    "create": "POST",
    "login": "POST",
    "signin": "POST",
    "signup": "POST",
    "register": "POST",
    "forgot": "POST",
    "reset": "POST",
    "verify": "POST",
    "upload": "POST",
    "download": "GET",
    "logout": "POST",
    "oauth": "POST",
    "token": "POST",
    "search": "GET",
    "filter": "GET",
    "fetch": "GET",
    "retrieve": "GET",
}

# File extensions that are NOT API endpoints
SKIP_SUFFIXES = (
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ttf", ".otf",
    ".woff", ".woff2", ".eot", ".mp3", ".mp4", ".wav", ".ogg", ".bin",
    ".so", ".pem", ".cer", ".p12", ".zip", ".apk", ".dex", ".jar",
    ".pdf", ".xml", ".json", ".txt", ".map", ".css", ".js", ".html",
    ".ico", ".dat", ".db", ".sql", ".proto", ".pb", ".o", ".a",
)

# Paths/domains to ignore (false positives, external links, etc.)
IGNORE_KEYWORDS = (
    "google-analytics",
    "doubleclick",
    "facebook.com/tr",
    "fonts.googleapis",
    "cdn-cgi",
    "youtrack.jetbrains",
    "github.com",
    "gitlab.com",
    "stackoverflow.com",
    "sentry.io",
    "rollbar.com",
    "bugsnag.com",
    "crashlytics",
    "firebase",
    "scheme",
    "schema",
    "w3.org",
    "w3c.org",
    "xmlns",
    "model.bin",
    "detector",
    "tracker",
    "features",
    "pdm_multires",
    "face_",
    "tflite",
    "onnx",
    "pb.txt",
    "_startup",
    "_prop.txt",
    "logcat",
    "anr_",
    "dump_state",
    "cache/",
    "assets/data",
    "assets/boost",
    "assets/fizz",
    "assets/hero",
    "assets/media",
    "assets/lib",
    "/system/",
    "/proc/",
    "/dev/",
    "/.well-known",
    "robots.txt",
    "favicon.ico",
    "apple-touch",
    "manifest.json",
    "openid-configuration",
    "oauth2/v1",
    "www.facebook.com",
    "m.facebook.com",
    "graph.facebook.com",
    "graph.instagram.com",
    "mqtt",
    "telemetry",
    "tracking",
    "analytics",
)

# Paths that look like they contain version numbers but are NOT API endpoints
FALSE_POSITIVE_PATTERNS = (
    r"/v\d+[a-z_].*\.bin",  # /v14/face_detector_model.bin
    r"/v\d+[a-z_].*model",
    r"[a-z_]*v\d+[a-z_]*\.(bin|dat|db|pb|proto|json|xml)",
    r"/\w+_\w+/v\d+",  # Like /selfiecapture/v14
)

REAL_API_PATTERNS = (
    r"/api/",
    r"/v\d+/[a-z]+",  # /v1/users
    r"/graphql",
    r"/oauth",
    r"/auth",
    r"/login",
    r"/signin",
    r"/signup",
    r"/register",
    r"/users",
    r"/profile",
    r"/account",
    r"/password",
    r"/email",
    r"/phone",
    r"/verify",
    r"/token",
    r"/refresh",
    r"/logout",
    r"/orders",
    r"/payments",
    r"/transactions",
    r"/products",
    r"/search",
    r"/upload",
    r"/download",
    r"/notifications",
    r"/messages",
    r"/comments",
    r"/posts",
    r"/feed",
    r"/settings",
    r"/preferences",
)


def is_likely_api_url(value: str) -> bool:
    """Aggressive false positive filtering."""
    value = value.strip().strip('"\'')
    if not value:
        return False

    lower = value.lower()

    # Reject known external/non-API domains
    if any(keyword in lower for keyword in IGNORE_KEYWORDS):
        return False

    # Reject known false positive patterns
    for pattern in FALSE_POSITIVE_PATTERNS:
        if re.search(pattern, lower, re.IGNORECASE):
            return False

    # Only accept if it matches a real API pattern
    has_api_pattern = any(re.search(pattern, lower) for pattern in REAL_API_PATTERNS)
    if not has_api_pattern:
        return False

    # Check file extension
    if any(lower.endswith(ext) for ext in SKIP_SUFFIXES):
        return False

    # Require either full URL or realistic path
    if lower.startswith("http://") or lower.startswith("https://"):
        parsed = urlparse(value)
        if not parsed.netloc:
            return False
        # Extra check: reject paths that look like assets
        path = parsed.path.lower()
        if any(path.endswith(ext) for ext in SKIP_SUFFIXES):
            return False
        # Reject single-letter paths like /V1fTq
        path_parts = [p for p in path.split("/") if p]
        if len(path_parts) == 1 and len(path_parts[0]) <= 5 and path_parts[0][0].isupper():
            return False
        return True

    # path-only fallback - must have API-like structure
    if value.startswith("/"):
        path_parts = [p for p in value.split("/") if p]
        # Reject single-letter or short random-looking parts
        if len(path_parts) == 1 and len(path_parts[0]) <= 5:
            return False
        return True

    return False


def normalize_raw_url(raw: str) -> str:
    raw = raw.strip().strip('"\'')
    if raw.startswith("http://") or raw.startswith("https://"):
        return raw
    if raw.startswith("/"):
        return raw
    return raw


def guess_method(raw_url: str, context: str = "") -> str:
    url_lower = raw_url.lower()
    ctx_lower = context.lower()
    combined = url_lower + " " + ctx_lower

    for key, method in METHOD_HINTS.items():
        if key in combined:
            return method

    path = urlparse(raw_url).path.lower() if raw_url.startswith("http") else raw_url.lower()
    if any(token in path for token in ("/login", "/signin", "/register", "/signup", "/auth", "/token", "/oauth", "/reset", "/verify", "/upload", "/create", "/post")):
        return "POST"
    if any(token in path for token in ("/search", "/filter", "/find", "/query", "/fetch", "/get", "/list", "/browse")):
        return "GET"
    return "GET"


def scan_text_blob(blob: bytes, context_name: str = "") -> set[str]:
    text = blob.decode("utf-8", errors="ignore")
    found: set[str] = set()

    # Full URLs first
    for match in URL_RE.findall(text):
        cleaned = normalize_raw_url(match)
        if is_likely_api_url(cleaned):
            found.add(cleaned)

    # Path-like references
    for match in PATH_RE.findall(text):
        cleaned = normalize_raw_url(match)
        if is_likely_api_url(cleaned):
            found.add(cleaned)

    return found


def extract_from_apk(apk_path: str) -> set[str]:
    urls: set[str] = set()
    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            for info in zf.infolist():
                name_lower = info.filename.lower()
                if any(name_lower.endswith(s) for s in SKIP_SUFFIXES):
                    continue
                try:
                    with zf.open(info, "r") as fh:
                        chunk = fh.read(2_000_000)
                except Exception:
                    continue
                if not chunk:
                    continue
                urls |= scan_text_blob(chunk, context_name=info.filename)
    except (zipfile.BadZipFile, Exception):
        pass
    return urls


def decompile_with_jadx(apk_path: str, timeout: int = 120) -> set[str]:
    if shutil.which("jadx") is None:
        return set()

    urls: set[str] = set()
    with tempfile.TemporaryDirectory(prefix="apk_endpoints_") as tmpdir:
        try:
            subprocess.run(
                ["jadx", "--no-res", "--no-imports", "-d", tmpdir, apk_path],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=timeout,
                check=False,
            )
        except (subprocess.TimeoutExpired, OSError):
            return set()

        for root, _, files in os.walk(tmpdir):
            for fn in files:
                if not fn.endswith((".java", ".kt", ".xml", ".txt", ".json")):
                    continue
                p = os.path.join(root, fn)
                try:
                    with open(p, "rb") as fh:
                        data = fh.read(2_000_000)
                except Exception:
                    continue
                urls |= scan_text_blob(data, context_name=fn)
    return urls


def normalize_output(urls: set[str]) -> list[str]:
    out: OrderedDict[str, None] = OrderedDict()
    for raw in sorted(urls):
        candidate = raw.strip().strip('"\'')
        if not candidate:
            continue
        if candidate.startswith("http://") or candidate.startswith("https://"):
            url = candidate
            method = guess_method(url)
            out[f"{method} {url}"] = None
        elif candidate.startswith("/"):
            method = guess_method(candidate)
            out[f"{method} {candidate}"] = None

    return list(out.keys())


def main() -> int:
    parser = argparse.ArgumentParser(description="Extract real API endpoints from an APK (with false positive filtering).")
    parser.add_argument("apk", help="Path to the APK file")
    parser.add_argument("-o", "--output", help="Write results to this file")
    parser.add_argument("--no-jadx", action="store_true", help="Skip jadx decompilation pass")
    parser.add_argument("--verbose", action="store_true", help="Show filtering details")
    args = parser.parse_args()

    apk = args.apk
    if not os.path.isfile(apk):
        print(f"[!] APK not found: {apk}", file=sys.stderr)
        return 1

    if args.verbose:
        print(f"[*] Scanning APK: {apk}")

    urls = set()
    urls |= extract_from_apk(apk)
    
    if args.verbose:
        print(f"[*] Found {len(urls)} URL candidates after ZIP scan")

    if not args.no_jadx:
        jadx_urls = decompile_with_jadx(apk)
        if jadx_urls and args.verbose:
            print(f"[*] Found {len(jadx_urls)} additional URL candidates after jadx decompilation")
        urls |= jadx_urls

    final = normalize_output(urls)

    if not final:
        print("[!] No real API endpoints found in this APK.", file=sys.stderr)
        return 0

    print(f"[+] Found {len(final)} API endpoint(s):\n")
    for line in final:
        print(line)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            for line in final:
                f.write(line + "\n")
        print(f"\n[+] Results saved to {args.output}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
