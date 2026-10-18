"""Deterministic counterparty-identity scoring (look-alike merchants).

Registry = merchants the operator knows (id, name, website, signing key). The checks:
  * exact registry membership by id
  * UTS#39-style skeleton of the display name (NFKC, case-fold, homoglyph fold) vs registry
  * Jaro-Winkler similarity of names, and of registrable domains (tldextract)
  * mixed-script detection on the name

These produce *facts*; the fraud pack decides ESCALATE/DENY. Stage 2 adds a Gemini
opinion on branding similarity that can only tighten.
"""

from __future__ import annotations

import unicodedata
from typing import Any

import tldextract
from rapidfuzz.distance import JaroWinkler

_HOMOGLYPHS = str.maketrans({
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "9": "g", "|": "l", "!": "i", "$": "s", "@": "a",
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "ɡ": "g", "ⅼ": "l",
    "ο": "o", "α": "a", "ν": "v", "ι": "i", "κ": "k", "ρ": "p", "τ": "t", "υ": "u", "ω": "w",
})
_MULTI = [("rn", "m"), ("vv", "w"), ("cl", "d"), ("nn", "m")]

_extract = tldextract.TLDExtract(suffix_list_urls=())  # offline, bundled PSL snapshot


def skeleton(name: str) -> str:
    s = unicodedata.normalize("NFKC", name or "").casefold()
    s = "".join(ch for ch in s if ch.isalnum())
    s = s.translate(_HOMOGLYPHS)
    for a, b in _MULTI:
        s = s.replace(a, b)
    return s


def registrable_domain(url_or_host: str) -> str:
    if not url_or_host:
        return ""
    ext = _extract(url_or_host)
    return ".".join(p for p in (ext.domain, ext.suffix) if p).lower()


def scripts_of(name: str) -> set[str]:
    out = set()
    for ch in name or "":
        if not ch.isalpha():
            continue
        try:
            n = unicodedata.name(ch)
        except ValueError:
            continue
        out.add(n.split(" ")[0])  # LATIN / CYRILLIC / GREEK ...
    return out


def score_counterparty(merchant: dict[str, Any], registry_entries: list[dict[str, Any]], *,
                       paid_before: bool, jw_threshold: float = 0.90) -> dict[str, Any]:
    mid = str(merchant.get("id") or "")
    name = str(merchant.get("name") or "")
    website = str(merchant.get("website") or "")
    dom = registrable_domain(website)
    sk = skeleton(name)
    known = any(e.get("id") == mid for e in registry_entries)
    best = {"id": "", "name": "", "name_similarity": 0.0, "domain_similarity": 0.0, "skeleton_collision": False}
    for e in registry_entries:
        if e.get("id") == mid:
            continue
        ns = JaroWinkler.similarity(sk, skeleton(str(e.get("name", ""))))
        edom = registrable_domain(str(e.get("website", "")))
        ds = JaroWinkler.similarity(dom, edom) if dom and edom else 0.0
        coll = bool(sk) and sk == skeleton(str(e.get("name", "")))
        if max(ns, ds) > max(best["name_similarity"], best["domain_similarity"]) or (coll and not best["skeleton_collision"]):
            best = {"id": str(e.get("id", "")), "name": str(e.get("name", "")), "name_similarity": round(ns, 4),
                    "domain_similarity": round(ds, 4), "skeleton_collision": coll}
    lookalike = best["id"] if (best["skeleton_collision"] or best["name_similarity"] >= jw_threshold or best["domain_similarity"] >= jw_threshold) else ""
    scr = scripts_of(name)
    return {
        "id": mid, "name": name, "website": website, "domain": dom, "skeleton": sk,
        "known": known, "first_time_for_user": not paid_before,
        "lookalike_of": lookalike,
        "lookalike_name": best["name"] if lookalike else "",
        "name_similarity": best["name_similarity"], "domain_similarity": best["domain_similarity"],
        "skeleton_collision": bool(best["skeleton_collision"]) and not known,
        "mixed_script": len(scr) > 1,
    }
