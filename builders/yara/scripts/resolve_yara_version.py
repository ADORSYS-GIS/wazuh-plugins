#!/usr/bin/env python3
"""Resolve the desired YARA release tag with optional GitHub auth and fallbacks."""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

API_URL = "https://api.github.com/repos/VirusTotal/yara/releases/latest"
RELEASE_URL = "https://github.com/VirusTotal/yara/releases/latest"
USER_AGENT = "wazuh-plugins-builder"


def _get_token() -> str | None:
    return os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")


def _request(url: str, *, headers: dict[str, str] | None = None, method: str | None = None):
    hdrs = {"User-Agent": USER_AGENT}
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, headers=hdrs, method=method or "GET")
    return urllib.request.urlopen(req, timeout=30)


def _resolve_via_api() -> str:
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = _get_token()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    with _request(API_URL, headers=headers) as resp:
        payload = json.load(resp)
    tag = payload.get("tag_name")
    if not tag:
        raise ValueError("GitHub API response did not include tag_name")
    return tag


def _resolve_via_redirect() -> str:
    with _request(RELEASE_URL) as resp:
        final_url = resp.geturl()
    if not final_url:
        raise ValueError("GitHub did not return a redirect URL")
    tag = final_url.rstrip("/").split("/")[-1]
    if not tag or tag == "latest":
        raise ValueError(f"Unable to parse release tag from redirect ({final_url})")
    return tag


def main() -> int:
    requested = os.environ.get("YARA_VERSION", "latest")
    if requested and requested != "latest":
        print(requested)
        return 0

    errors: list[str] = []
    for resolver in (_resolve_via_api, _resolve_via_redirect):
        try:
            tag = resolver()
        except (urllib.error.URLError, urllib.error.HTTPError, ValueError) as exc:
            errors.append(f"{resolver.__name__} failed: {exc}")
        else:
            print(tag)
            return 0

    for msg in errors:
        print(msg, file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
