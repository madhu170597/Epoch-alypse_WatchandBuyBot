"""Pages the agent says it read are its own report. For pages on a registered merchant's site, MandateGuard fetches
its own copy and compares, so a compromised agent can't hide or rewrite what the merchant actually published.

Only https, only hosts the operator registered as a merchant website, never private or link-local addresses, no
redirects, at most 600 kB. The address check runs before the request; hosts are operator-registered, which is what
keeps DNS rebinding out of scope here.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
import socket
from typing import Any, Callable
from urllib.parse import urlsplit

MAX_BYTES = 600_000


class FetchRefused(Exception):
    pass


def normalize(text: str) -> str:
    return re.sub(r"\s+", " ", text or "").strip()


def text_sha256(text: str) -> str:
    return hashlib.sha256(normalize(text).encode("utf-8")).hexdigest()


def host_of(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def merchant_hosts(profiles: list[dict[str, Any]]) -> set[str]:
    return {h for h in (host_of(str(p.get("website", ""))) for p in profiles) if h}


def public_address(host: str) -> bool:
    try:
        infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
    except OSError:
        return False
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified:
            return False
    return bool(infos)


class HttpPageFetcher:
    def __init__(self, timeout_s: float = 3.0):
        self.timeout = timeout_s

    def __call__(self, url: str) -> str:
        import httpx

        if not public_address(host_of(url)):
            raise FetchRefused("the address is not public")
        with httpx.Client(timeout=self.timeout, follow_redirects=False, headers={"User-Agent": "MandateGuard page check"}) as c:
            with c.stream("GET", url) as r:
                if r.status_code != 200:
                    raise FetchRefused(f"HTTP {r.status_code}")
                buf = bytearray()
                for chunk in r.iter_bytes():
                    buf += chunk
                    if len(buf) > MAX_BYTES:
                        raise FetchRefused("page larger than 600 kB")
                return bytes(buf).decode(r.encoding or "utf-8", errors="replace")


def confirm_pages(pages: list[Any], hosts: set[str], fetch: Callable[[str], str] | None) -> list[dict[str, Any]]:
    """One result per page: whether MandateGuard fetched its own copy, and whether it matches the agent's.
    The fetched text is returned under `text` for screening; callers must not put it in a public record."""
    out = []
    for p in pages:
        u = urlsplit(p.url) if "://" in p.url else None
        host = host_of(p.url)
        res: dict[str, Any] = {"url": p.url, "host": host, "agent_sha256": text_sha256(p.content), "fetched": False, "matches": None, "reason": ""}
        if fetch is None:
            res["reason"] = "page checks are off"
        elif u is None or u.scheme != "https":
            res["reason"] = "not an https address"
        elif host not in hosts:
            res["reason"] = "not a registered merchant site"
        else:
            try:
                text = fetch(p.url)
                sha = text_sha256(text)
                res.update(fetched=True, fetched_sha256=sha, matches=sha == res["agent_sha256"], text=text)
            except Exception as e:  # noqa: BLE001 - an unreachable page is recorded, not fatal
                res["reason"] = f"could not fetch: {e}"[:200]
        out.append(res)
    return out
