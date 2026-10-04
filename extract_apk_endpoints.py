#!/usr/bin/env python3
"""Extract likely API endpoints from an Android APK.

This script is intentionally conservative:
- It scans the APK as a ZIP archive.
- It optionally decompiles with jadx if present.
- It extracts URL-like strings and API-like paths.
- It normalizes them to method + URL lines such as:
    GET https://api.example.com/v1/users
    POST https://api.example.com/login

Usage:
    python3 extract_apk_endpoints.py app.apk
    python3 extract_apk_endpoints.py app.apk --output endpoints.txt
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
}

SKIP_SUFFIXES = (
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ttf", ".otf",
    ".woff", ".woff2", ".eot", ".mp3", ".mp4", ".wav", ".ogg", ".bin",
    ".so", ".pem", ".cer", ".p12", ".zip", ".apk", ".dex", ".jar",
)

IGNORE_PATHS = (
    "google-analytics", "doubleclick", "facebook.com/tr", "fonts.googleapis",
    "cdn-cgi", "/.well-known/assetlinks.json", "/robots.txt", "/favicon.ico",
)


def is_likely_api_url(value: str) -> bool:
    value = value.strip().strip('"\'')
    if not value:
        return False
    lower = value.lower()
    if lower.startswith("http://schemas.android.com"):
        return False
    if "googleapis" in lower and "/maps" in lower:
        return False
    if any(noise in lower for noise in IGNORE_PATHS):
        return False
    if lower.startswith("http://") or lower.startswith("https://"):
        parsed = urlparse(value)
        if not parsed.netloc:
            return False
        path = parsed.path.lower()
        if path.endswith((".png", ".jpg", ".jpeg", ".gif", ".svg", ".css", ".js", ".ico", ".woff", ".woff2", ".pdf", ".map")):
            return False
        return True
    # path-only fallback
    path = value.lower()
    if path.startswith("/") and any(token in path for token in ("/api", "/v1", "/v2", "/graphql", "/oauth", "/auth", "/login", "/register", "/users", "/orders", "/payments", "/profile", "/mobile")):
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
    if any(token in path for token in ("/login", "/signin", "/register", "/signup", "/auth", "/token", "/oauth", "/reset", "/verify", "/upload")):
        return "POST"
    if any(token in path for token in ("/search", "/filter", "/find", "/query")):
        return "GET"
    return "GET"


def scan_text_blob(blob: bytes, context_name: str = "") -> set[str]:
    text = blob.decode("utf-8", errors="ignore")
    found: set[str] = set()

    # Full URLs first.
    for match in URL_RE.findall(text):
        cleaned = normalize_raw_url(match)
        if is_likely_api_url(cleaned):
            found.add(cleaned)

    # Path-like references.
    for match in PATH_RE.findall(text):
        cleaned = normalize_raw_url(match)
        if is_likely_api_url(cleaned):
            found.add(cleaned)

    # Try some strings where URL is split by string concatenation.
    # Example: "https://" + host + "/api" becomes a token no longer matching URL_RE.
    # We keep the best effort by searching for api/vN-like fragments.
    for fragment in re.findall(r"(?:https?://|/)(?:api|v\d+|graphql|oauth|auth|login|users|orders|payments|profile)[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]*", text, re.IGNORECASE):
        cleaned = normalize_raw_url(fragment)
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
    except zipfile.BadZipFile:
        pass
    except Exception:
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
            # Fallback if we only extracted a path without a host.
            out[f"GET {candidate}"] = None
        else:
            out[f"GET {candidate}"] = None
    return list(out.keys())


def main() -> int:
    parser = argparse.ArgumentParser(description="Extract likely API endpoints from an APK.")
    parser.add_argument("apk", help="Path to the APK file")
    parser.add_argument("-o", "--output", help="Write results to this file")
    parser.add_argument("--no-jadx", action="store_true", help="Skip jadx decompilation pass")
    args = parser.parse_args()

    apk = args.apk
    if not os.path.isfile(apk):
        print(f"[!] APK not found: {apk}", file=sys.stderr)
        return 1

    urls = set()
    urls |= extract_from_apk(apk)
    if not args.no_jadx:
        urls |= decompile_with_jadx(apk)

    final = normalize_output(urls)

    if not final:
        print("[!] No API endpoint-like URLs found in this APK.")
        return 0

    for line in final:
        print(line)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            for line in final:
                f.write(line + "\n")
        print(f"\n[+] Saved {len(final)} endpoint(s) to {args.output}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
