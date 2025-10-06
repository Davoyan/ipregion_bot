"""Helpers to work with subscription-based proxy lists."""
from __future__ import annotations

import base64
from typing import Any
from urllib.parse import urlparse

import aiohttp

from services.proxy import extract_proxy_uris


def _b64fix(value: str) -> str:
    return value + "=" * (-len(value) % 4)


def _append_proxies(container: list[str], candidate: str, seen: set[str]) -> None:
    for uri in extract_proxy_uris(candidate):
        if uri not in seen:
            seen.add(uri)
            container.append(uri)


async def fetch_subscription_proxies(
    url: str,
    outbound_proxy: str | None = None,
) -> list[str]:
    try:
        parsed = urlparse(url.strip())
    except Exception:
        return []

    if parsed.scheme not in {"http", "https"}:
        return []
    if not parsed.path or parsed.path == "/":
        return []

    headers = {
        "User-Agent": "ipregion-bot",
        "X-HWID": "e8444c64-212c-4cbb-b7ca-9347a0f260f1",
    }
    timeout = aiohttp.ClientTimeout(total=15)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        request_kwargs: dict[str, Any] = {"headers": headers}
        if outbound_proxy:
            request_kwargs["proxy"] = outbound_proxy
        async with session.get(url, **request_kwargs) as response:
            response.raise_for_status()
            text = await response.text()

    compact = "".join(text.strip().split())
    try:
        decoded = base64.urlsafe_b64decode(_b64fix(compact))
    except Exception:
        try:
            decoded = base64.b64decode(_b64fix(compact))
        except Exception:
            proxies_plain: list[str] = []
            seen_plain: set[str] = set()
            for line in (text or "").splitlines():
                candidate = line.strip()
                if candidate:
                    _append_proxies(proxies_plain, candidate, seen_plain)
            return proxies_plain

    decoded_text = decoded.decode("utf-8", errors="ignore")
    proxies: list[str] = []
    seen: set[str] = set()
    for line in decoded_text.splitlines():
        candidate = line.strip()
        if candidate:
            _append_proxies(proxies, candidate, seen)
    return proxies


__all__ = [
    "fetch_subscription_proxies",
]
