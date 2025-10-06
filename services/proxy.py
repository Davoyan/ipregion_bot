"""Utility helpers to work with proxy URIs."""
from __future__ import annotations

import base64
import json
import re
import string
from urllib.parse import parse_qs, unquote, unquote_plus, urlparse

PROXY_SCHEMES: tuple[str, ...] = ("vless", "trojan", "vmess", "ss")
PROXY_PATTERN = re.compile(rf"(?i)\\b(?:{'|'.join(PROXY_SCHEMES)})://[^\\s]+")
_HEX_CHARS = set(string.hexdigits)


def _b64fix(value: str) -> str:
    """Pad Base64 strings to a valid length."""
    return value + "=" * (-len(value) % 4)


def _qdict(query: str) -> dict[str, str]:
    """Return a lower-cased mapping for URL query parameters."""
    return {key.lower(): values[0] for key, values in parse_qs(query).items()}


def extract_proxy_uris(text: str | None) -> list[str]:
    """Return proxy URIs found in the provided text."""
    if not text:
        return []

    raw_text = text.strip()
    if not raw_text:
        return []

    seen: set[str] = set()
    uris: list[str] = []
    for match in PROXY_PATTERN.finditer(raw_text):
        uri = match.group(0).rstrip(")]\n\r\t,.;")
        if uri and uri not in seen:
            seen.add(uri)
            uris.append(uri)

    if uris:
        return uris

    fallback = raw_text.rstrip(")]\n\r\t,.;")
    if "://" in fallback:
        scheme = fallback.split("://", 1)[0].lower()
        if scheme in PROXY_SCHEMES:
            return [fallback]

    return []


def _decode_fragment(fragment: str | None) -> tuple[str | None, bool]:
    if not fragment:
        return None, False

    cleaned = fragment
    truncated = False

    while cleaned:
        if cleaned.endswith("%"):
            cleaned = cleaned[:-1]
            truncated = True
            continue
        if len(cleaned) >= 2 and cleaned[-2] == "%" and cleaned[-1] in _HEX_CHARS:
            cleaned = cleaned[:-2]
            truncated = True
            continue
        break

    try:
        decoded = unquote_plus(cleaned)
    except Exception:
        decoded = unquote(cleaned, encoding="utf-8", errors="ignore")

    decoded = decoded or ""
    if truncated:
        decoded = decoded.rstrip()

    if not decoded:
        return None, truncated

    return decoded, truncated


def parse_proxy_uri(uri: str) -> dict[str, str | int | None]:
    """Parse a proxy URI into a structured mapping."""
    parsed = urlparse((uri or "").strip())
    scheme = (parsed.scheme or "").lower()
    comment, comment_truncated = _decode_fragment(parsed.fragment)

    if scheme in {"vless", "trojan"}:
        query_params = _qdict(parsed.query)
        base: dict[str, str | int | None] = {
            "protocol": scheme,
            "port": parsed.port,
            "type": query_params.get("type"),
            "sni": query_params.get("sni"),
            "host": query_params.get("host"),
            "server": parsed.hostname,
            "comment": comment,
            "comment_truncated": comment_truncated,
        }
        if scheme == "vless":
            base["security"] = query_params.get("security")
        return base

    if scheme == "vmess":
        if not parsed.netloc and parsed.path:
            try:
                raw = base64.urlsafe_b64decode(_b64fix(parsed.path)).decode()
                config = json.loads(raw)
            except Exception:
                return {
                    "protocol": "vmess",
                    "type": "vmess",
                    "port": None,
                    "sni": None,
                    "host": None,
                    "server": None,
                    "comment": comment,
                    "comment_truncated": comment_truncated,
                }
            network_type = (
                config.get("type")
                or config.get("net")
                or config.get("network")
            )
            sni_value = (
                config.get("sni")
                or config.get("peer")
                or config.get("servername")
            )
            ws_opts = config.get("ws-opts") or {}
            headers = ws_opts.get("headers") or {}
            host_header = headers.get("Host")
            return {
                "protocol": "vmess",
                "port": config.get("port"),
                "type": network_type,
                "sni": sni_value,
                "host": config.get("host") or host_header,
                "server": (
                    config.get("add")
                    or config.get("address")
                    or config.get("server")
                ),
                "comment": comment,
                "comment_truncated": comment_truncated,
            }
        query_params = _qdict(parsed.query)
        return {
            "protocol": "vmess",
            "port": parsed.port,
            "type": query_params.get("type"),
            "sni": query_params.get("sni")
            or query_params.get("peer")
            or query_params.get("servername"),
            "host": query_params.get("host") or query_params.get("authority"),
            "server": parsed.hostname,
            "comment": comment,
            "comment_truncated": comment_truncated,
        }

    if scheme == "ss":
        netloc = parsed.netloc or ""

        if "@" in netloc:
            userinfo, hostport = netloc.rsplit("@", 1)
            try:
                decoded_userinfo = base64.urlsafe_b64decode(
                    _b64fix(userinfo)
                ).decode()
                if ":" in decoded_userinfo:
                    netloc = f"{decoded_userinfo}@{hostport}"
            except Exception:
                pass
        elif not netloc and parsed.path:
            try:
                decoded_full = base64.urlsafe_b64decode(
                    _b64fix(parsed.path)
                ).decode()
                if "@" in decoded_full:
                    netloc = decoded_full
            except Exception:
                pass

        method, host, port = None, None, None
        if "@" in netloc:
            creds, hostport = netloc.rsplit("@", 1)
            if ":" in creds:
                method = creds.split(":", 1)[0]
            host_str, port_str = None, None
            if hostport.startswith("["):
                right_brace = hostport.find("]")
                if right_brace != -1:
                    host_str = hostport[1:right_brace]
                    rest = hostport[right_brace + 1 :]
                    if rest.startswith(":"):
                        port_str = rest[1:]
            else:
                if ":" in hostport:
                    host_str, port_str = hostport.rsplit(":", 1)
            host = host_str
            try:
                port = int(port_str) if port_str else None
            except Exception:
                port = None

        return {
            "protocol": "ss",
            "port": port,
            "method": method,
            "server": host,
            "comment": comment,
            "comment_truncated": comment_truncated,
        }

    if scheme in PROXY_SCHEMES:
        return {
            "protocol": scheme,
            "comment": comment,
            "comment_truncated": comment_truncated,
        }

    return {
        "protocol": scheme or "unknown",
        "comment": comment,
        "comment_truncated": comment_truncated,
    }


__all__ = [
    "PROXY_PATTERN",
    "PROXY_SCHEMES",
    "extract_proxy_uris",
    "parse_proxy_uri",
]
