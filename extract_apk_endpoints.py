#!/usr/bin/env python3
"""APK API Endpoint Extractor (Clean Version)

Purpose:
- Extract real API endpoints from an APK
- Keep only endpoints with real API-like structure
- Ignore binaries, docs, random strings, and static asset URLs
- Output in the format:
    GET https://api.example.com/v1/users
    POST https://api.example.com/login

Why this version is better:
- Stricter filtering than generic regex extractors
- Removes false positives like .bin, .png, docs, Facebook, random strings
- Works well with apps like YouTube / large APKs

Usage:
    python3 extract_apk_endpoints.py app.apk
    python3 extract_apk_endpoints.py app.apk --output endpoints.txt
    python3 extract_apk_endpoints.py app.apk --no-jadx
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

# --- Constants ---
URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
PATH_RE = re.compile(
    r"(?:/|https?://)[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+(?:/api|/v\d+|/graphql|/oauth|/auth|/login|/signin|/signup|/register|/users|/profile|/account|/token|/refresh|/verify|/notifications|/search|/orders|/payment|/payments|/products|/comments|/posts|/feed|/messages|/upload|/download|/settings)[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]*",
    re.IGNORECASE,
)

METHOD_HINTS = {
    "login": "POST",
    "signin": "POST",
    "signup": "POST",
    "register": "POST",
    "auth": "POST",
    "oauth": "POST",
    "token": "POST",
    "verify": "POST",
    "reset": "POST",
    "update": "PUT",
    "create": "POST",
    "delete": "DELETE",
    "upload": "POST",
    "download": "GET",
    "search": "GET",
    "filter": "GET",
    "query": "GET",
    "fetch": "GET",
    "get": "GET",
    "list": "GET",
    "orders": "GET",
    "products": "GET",
    "profile": "GET",
    "settings": "GET",
    "notifications": "GET",
    "messages": "GET",
}

SKIP_SUFFIXES = (
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ttf", ".otf",
    ".woff", ".woff2", ".eot", ".mp3", ".mp4", ".wav", ".ogg", ".bin",
    ".so", ".pem", ".cer", ".p12", ".zip", ".apk", ".dex", ".jar",
    ".pdf", ".map", ".css", ".js", ".html", ".xml", ".json", ".txt",
    ".ico", ".dat", ".db", ".sqlite", ".proto", ".pb", ".wasm",
)

FALSE_POSITIVE_PATTERNS = (
    r"/v\d+[a-z_].*\.bin",
    r"/v\d+[a-z_].*model",
    r"/assets/",
    r"/cache/",
    r"/system/",
    r"/proc/",
    r"/dev/",
    r"/\.well-known/",
    r"/google-analytics",
    r"/doubleclick",
    r"/favicon\.ico",
    r"/robots\.txt",
    r"facebook\.com",
    r"instagram\.com",
    r"youtube\.com/api/lounge",
    r"youtubei\.googleapis\.com/generate_204",
    r"google\.com/maps",
    r"support\.google\.com",
    r"docs\.google\.com",
    r"docs\.microsoft\.com",
    r"microsoft\.com",
    r"www\.apache\.org",
    r"creativecommons\.org",
    r"www\.khronos\.org",
    r"github\.com",
    r"youtrack",
    r"hubspotdocuments",
)

# The app might include many Google internal URLs in libraries and assets, but these are not always app backend API endpoints.
# We retain a small set of tightly-scoped patterns to keep quality high.
REAL_API_PATTERNS = (
    r"/api/",
    r"/v1/",
    r"/v2/",
    r"/v3/",
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
    r"/token",
    r"/refresh",
    r"/verify",
    r"/notifications",
    r"/orders",
    r"/payments",
    r"/products",
    r"/comments",
    r"/posts",
    r"/feed",
    r"/messages",
    r"/search",
    r"/upload",
    r"/download",
    r"/settings",
)

# --- Helper functions ---

def normalize_url(raw: str) -> str:
    raw = raw.strip().strip('"\'')
    if not raw:
        return ""
    if raw.endswith(("(", ")", "[", "]", "{", "}")):
        raw = raw.rstrip("()[]{}")
    return raw


def is_likely_api_candidate(value: str) -> bool:
    value = normalize_url(value)
    if not value:
        return False

    lower = value.lower()
    if not (lower.startswith("http://") or lower.startswith("https://") or lower.startswith("/")):
        return False

    # Remove obvious false positives
    if any(lower.endswith(ext) for ext in SKIP_SUFFIXES):
        return False

    for pattern in FALSE_POSITIVE_PATTERNS:
        if re.search(pattern, lower, re.IGNORECASE):
            return False

    # Require at least one API-like pattern
    if not any(re.search(p, lower, re.IGNORECASE) for p in REAL_API_PATTERNS):
        return False

    # If it's a full URL, make sure it includes a netloc and not a random doc link
    if lower.startswith("http://") or lower.startswith("https://"):
        try:
            parsed = urlparse(value)
            if not parsed.netloc:
                return False
        except Exception:
            return False
        # Reject weird links with no real hostname component or with a single random token
        if parsed.netloc.split(".") and len(parsed.netloc.split(".")) == 1 and len(parsed.netloc) < 8:
            return False

    return True


def guess_method(url: str) -> str:
    lower = url.lower()

    for token, method in METHOD_HINTS.items():
        if token in lower:
            return method

    if any(k in lower for k in ("/login", "/signin", "/register", "/signup", "/auth", "/token", "/oauth", "/verify", "/refresh", "/upload", "/reset")):
        return "POST"
    if any(k in lower for k in ("/search", "/filter", "/query", "/list", "/download", "/get", "/stats")):
        return "GET"
    return "GET"


def scan_blob(blob: bytes) -> set[str]:
    text = blob.decode("utf-8", errors="ignore")
    found: set[str] = set()

    # Full URL capture first
    for match in URL_RE.findall(text):
        candidate = normalize_url(match)
        if is_likely_api_candidate(candidate):
            found.add(candidate)

    # Path-like API capture second
    for match in PATH_RE.findall(text):
        candidate = normalize_url(match)
        if is_likely_api_candidate(candidate):
            found.add(candidate)

    return found


def extract_from_zip(apk_path: str) -> set[str]:
    urls: set[str] = set()
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
            urls |= scan_blob(chunk)
    return urls


def decompile_with_jadx(apk_path: str) -> set[str]:
    if shutil.which("jadx") is None:
        return set()

    urls: set[str] = set()
    with tempfile.TemporaryDirectory(prefix="apk_api_extract_") as tmpdir:
        try:
            subprocess.run(
                ["jadx", "--no-res", "--no-imports", "-d", tmpdir, apk_path],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=120,
                check=False,
            )
        except Exception:
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
                urls |= scan_blob(data)
    return urls


def finalize(urls: set[str]) -> list[str]:
    result: OrderedDict[str, None] = OrderedDict()
    for raw in sorted(urls):
        candidate = normalize_url(raw)
        if not candidate:
            continue
        method = guess_method(candidate)
        result[f"{method} {candidate}"] = None
    return list(result.keys())


def main() -> int:
    parser = argparse.ArgumentParser(description="Extract likely API endpoints from an APK file.")
    parser.add_argument("apk", help="Path to APK file")
    parser.add_argument("-o", "--output", help="Write output to a file")
    parser.add_argument("--no-jadx", action="store_true", help="Skip jadx decompilation pass")
    args = parser.parse_args()

    apk = args.apk
    if not os.path.isfile(apk):
        print(f"[!] APK not found: {apk}", file=sys.stderr)
        return 1

    urls: set[str] = set()
    urls |= extract_from_zip(apk)
    if not args.no_jadx:
        urls |= decompile_with_jadx(apk)

    endpoints = finalize(urls)

    if not endpoints:
        print("[!] No real API endpoints found in this APK.")
        return 0

    print(f"[+] Found {len(endpoints)} real API endpoint(s):\n")
    for line in endpoints:
        print(line)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            for line in endpoints:
                f.write(line + "\n")
        print(f"\n[+] Saved results to {args.output}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
