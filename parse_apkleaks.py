#!/usr/bin/env python3
"""
Extract API endpoints from APKLeaks output.
Parses apkleaks text file and extracts ONLY real API endpoints.
"""

import argparse
import re
import sys
from collections import OrderedDict

# Real API domain patterns
REAL_API_DOMAINS = (
    "googleapis.com",
    "youtube.com",
    "youtrack",
    "api.",
    "sandbox.",
    "staging-",
)

SKIP_DOMAINS = (
    "www.w3.org",
    "www.w3c.org",
    "xmlns",
    "schemas.android.com",
    "github.com",
    "facebook.com",
    "instagram.com",
)

# Real API path patterns
API_PATH_PATTERNS = (
    "/api/",
    "/v1/",
    "/v2/",
    "/v3/",
    "/graphql",
    "/oauth",
    "/oauth2",
    "/auth",
    "/login",
    "/signin",
    "/register",
    "/signup",
    "/users",
    "/profile",
    "/account",
    "/token",
    "/refresh",
    "/verify",
    "/notifications",
    "/fcm",
    "/projects/",
    "/generate_204",
    "/reauth",
)


def is_real_api_endpoint(url: str) -> bool:
    """Check if URL is a real API endpoint (not asset, not external)."""
    url = url.strip().strip('"\'')
    if not url:
        return False

    lower = url.lower()

    # Must start with http
    if not (lower.startswith("http://") or lower.startswith("https://")):
        return False

    # Reject known non-API domains
    if any(skip in lower for skip in SKIP_DOMAINS):
        return False

    # Must have real API domain OR real API path
    has_api_domain = any(api_domain in lower for api_domain in REAL_API_DOMAINS)
    has_api_path = any(path_pattern in lower for path_pattern in API_PATH_PATTERNS)

    if not (has_api_domain or has_api_path):
        return False

    # Reject obviously broken URLs (with trailing characters)
    if url.endswith(("(", ")", "[", "]", "{", "}")):
        return False

    # Reject URLs that are too short or obviously not endpoints
    if len(url) < 20:
        return False

    return True


def guess_method(url: str) -> str:
    """Guess HTTP method from URL path."""
    lower = url.lower()
    
    if any(token in lower for token in ("/login", "/signin", "/register", "/signup", "/auth", "/token", "/oauth", "/verify", "/reset", "/upload", "/create", "/post")):
        return "POST"
    
    if any(token in lower for token in ("/search", "/filter", "/find", "/query", "/get", "/list", "/browse", "/download", "/stats", "/generate_204")):
        return "GET"
    
    return "GET"


def extract_urls_from_apkleaks(text: str) -> set[str]:
    """Extract URLs from apkleaks output."""
    urls = set()
    
    # Pattern: https://... or http://...
    url_pattern = re.compile(r"https?://[^\s\)\"\']+", re.IGNORECASE)
    
    for line in text.split("\n"):
        for match in url_pattern.findall(line):
            urls.add(match.strip())
    
    return urls


def main():
    parser = argparse.ArgumentParser(description="Extract real API endpoints from APKLeaks output")
    parser.add_argument("apkleaks_output", help="APKLeaks output file")
    parser.add_argument("-o", "--output", help="Write results to this file")
    parser.add_argument("--include-paths-only", action="store_true", help="Include path-only endpoints (no full URL)")
    args = parser.parse_args()

    try:
        with open(args.apkleaks_output, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except FileNotFoundError:
        print(f"[!] File not found: {args.apkleaks_output}", file=sys.stderr)
        return 1

    urls = extract_urls_from_apkleaks(content)
    
    # Filter to real API endpoints
    real_endpoints = OrderedDict()
    for url in sorted(urls):
        if is_real_api_endpoint(url):
            method = guess_method(url)
            endpoint = f"{method} {url}"
            real_endpoints[endpoint] = None

    if not real_endpoints:
        print("[!] No real API endpoints found.", file=sys.stderr)
        return 0

    print(f"[+] Found {len(real_endpoints)} real API endpoint(s):\n")
    for endpoint in real_endpoints.keys():
        print(endpoint)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            for endpoint in real_endpoints.keys():
                f.write(endpoint + "\n")
        print(f"\n[+] Results saved to {args.output}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
