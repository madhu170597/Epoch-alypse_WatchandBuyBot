"""Stage 0/2 injection screen on fetched merchant page content.

Two screeners, combined with "stricter wins":
  * ModelArmorScreener  - Google Cloud Model Armor prompt-injection/jailbreak filter (regional API)
  * HeuristicScreener   - local patterns for the attack classes Model Armor was measured to miss
                          (polite instructions to agents, text addressed to MandateGuard, JSON-LD /
                          HTML-comment payloads). Always on; cheap; produces explainable signals.

Output is a plain fact dict consumed by the fraud pack; the screen never ALLOWs anything.
"""

from __future__ import annotations

import html
import re
from typing import Any

CONF_ORDER = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}

_GUARD_TARGET = re.compile(r"\b(mandate\s*guard|mandateguard|guardrail|verifier|verification agent|policy engine)\b", re.I)
_AGENT_TARGET = re.compile(r"\b(ai agents?|assistants?|shopping agents?|automated shoppers?|agents?|bots?|llms?|language models?|system notice|system message)\b", re.I)
_OVERRIDE = re.compile(r"\b(ignore|disregard|override|bypass|forget)\b.{0,40}\b(instructions?|rules?|previous|prior|constraints?|mandate)\b", re.I)
_VERDICT_WORDS = re.compile(r"\b(return|verdict|respond with|output|mark|set)\b.{0,30}\b(allow|approved?|ok|safe|pass)\b", re.I)
_PREAPPROVED = re.compile(r"\b(pre[- ]?approved|already (?:been )?(?:approved|verified|checked)|verification (?:already )?completed)\b", re.I)
_CART_MUTATION = re.compile(r"\b(add|include|append|requires?)\b.{0,60}\b(sku|item|gift ?card|bundle|warranty|insurance|case)\b|\b(change|update|set|use)\b.{0,40}\b(shipping|delivery|address|payee|recipient|account)\b|\bship (it )?to\b", re.I)
_HIDDEN_BLOCKS = [
    ("html_comment", re.compile(r"<!--(.*?)-->", re.S)),
    ("json_ld", re.compile(r"<script[^>]*application/ld\+json[^>]*>(.*?)</script>", re.S | re.I)),
    ("hidden_style", re.compile(r"<[^>]+(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0)[^>]*>(.*?)</", re.S | re.I)),
    ("meta_content", re.compile(r"<meta[^>]+content=\"([^\"]{40,})\"", re.I)),
]
_AGENT_STRICT = re.compile(r"\b(ai agents?|shopping agents?|automated shoppers?|(?:ai|shopping|virtual) assistants?|shopping bots?|llms?|language models?)\b", re.I)
_IMPERATIVE = re.compile(r"\b(must|should|need to|required to|requires?|please|always|make sure)\b", re.I)
_SENTENCE = re.compile(r"(?<=[.!?])\s+|\n+")
_AGENT_KEYS = re.compile(r"\"(agent_?instructions?|ai_?instructions?|assistant_?note|llm_?hint|bot_?directive)\"\s*:", re.I)


_WHERE = {"body": "Visible page text", "html_comment": "Hidden HTML comment", "json_ld": "Structured data (JSON-LD)",
          "hidden_style": "Hidden element", "meta_content": "Meta tag"}
_TAGS = re.compile(r"<[^>]+>")


def _excerpt(seg: str, rx: re.Pattern | None) -> str:
    """The sentence that triggered, tags stripped, whitespace collapsed. Shown as quoted evidence."""
    text = seg
    if rx is not None:
        m = rx.search(seg)
        if m:
            text = seg[max(0, m.start() - 90): m.end() + 140]
    text = " ".join(_TAGS.sub(" ", text).split())
    return text[:280]


class HeuristicScreener:
    name = "heuristic"

    def screen(self, text: str) -> dict[str, Any]:
        signals: list[str] = []
        excerpts: list[dict[str, str]] = []
        raw = html.unescape(text or "")
        hidden_segments: list[tuple[str, str]] = []
        visible = raw
        for label, rx in _HIDDEN_BLOCKS:
            for m in rx.finditer(raw):
                hidden_segments.append((label, m.group(1)))
            visible = rx.sub(" ", visible)
        segments: list[tuple[str, str]] = [("body", visible)] + hidden_segments
        addressed_to_guard = False
        conf = "NONE"

        def bump(level: str, sig: str, where: str | None = None, seg: str | None = None, rx: re.Pattern | None = None) -> None:
            nonlocal conf
            signals.append(sig)
            if where is not None and seg is not None:
                ex = {"where": _WHERE.get(where, where), "text": _excerpt(seg, rx)}
                if ex["text"] and ex not in excerpts:
                    excerpts.append(ex)
            if CONF_ORDER[level] > CONF_ORDER[conf]:
                conf = level

        for label, seg in segments:
            hidden = label != "body"
            units = [seg] if hidden else [u for u in _SENTENCE.split(seg) if u.strip()]
            for unit in units:
                if _GUARD_TARGET.search(unit):
                    addressed_to_guard = True
                    if _VERDICT_WORDS.search(unit) or _PREAPPROVED.search(unit):
                        bump("HIGH", f"{label}: text addressed to the verifier asking for approval", label, unit, _GUARD_TARGET)
                    else:
                        bump("MEDIUM", f"{label}: text mentions the verifier", label, unit, _GUARD_TARGET)
                if _OVERRIDE.search(unit):
                    bump("HIGH", f"{label}: override/ignore-instructions phrasing", label, unit, _OVERRIDE)
                if hidden:
                    if label == "json_ld" and _AGENT_KEYS.search(unit):
                        bump("HIGH", "structured data carries a field addressed to agents", label, unit, _AGENT_KEYS)
                    elif _CART_MUTATION.search(unit) and _AGENT_TARGET.search(unit):
                        bump("HIGH", f"{label}: hidden instruction to change cart, shipping or payee", label, unit, None)
                    elif _AGENT_TARGET.search(unit):
                        # text people cannot see, written for software that shops: there is no benign reading
                        bump("HIGH", f"{label}: hidden text addressed to agents", label, unit, None)
                else:
                    if not _AGENT_STRICT.search(unit):
                        continue
                    if _CART_MUTATION.search(unit):
                        bump("MEDIUM", "visible text tells agents to change the cart", label, unit, None)
                    elif _IMPERATIVE.search(unit):
                        bump("LOW", "visible text gives instructions to agents", label, unit, None)
        # hidden blocks are shown whole when they triggered; drop body excerpts that just repeat them
        return {"provider": self.name, "match": conf != "NONE", "confidence": conf,
                "signals": signals[:12], "addressed_to_guard": addressed_to_guard, "excerpts": excerpts[:6]}


class ModelArmorScreener:
    """Google Cloud Model Armor sanitizeUserPrompt on page text."""

    name = "model-armor"

    def __init__(self, project: str, location: str, template_id: str, credentials: Any = None):
        from google.api_core.client_options import ClientOptions
        from google.cloud import modelarmor_v1

        self._mod = modelarmor_v1
        self.template = f"projects/{project}/locations/{location}/templates/{template_id}"
        kwargs: dict[str, Any] = {"transport": "rest", "client_options": ClientOptions(api_endpoint=f"modelarmor.{location}.rep.googleapis.com")}
        if credentials is not None:
            kwargs["credentials"] = credentials
        self.client = modelarmor_v1.ModelArmorClient(**kwargs)

    def screen(self, text: str) -> dict[str, Any]:
        m = self._mod
        try:
            resp = self.client.sanitize_user_prompt(request=m.SanitizeUserPromptRequest(
                name=self.template, user_prompt_data=m.DataItem(text=text[:250_000])))
        except Exception as e:  # noqa: BLE001 - unavailable screener is a LOW signal, never fail-open silently
            return {"provider": self.name, "match": False, "confidence": "NONE", "signals": [f"model armor unavailable: {e}"],
                    "addressed_to_guard": False, "error": str(e)}
        r = resp.sanitization_result
        signals: list[str] = []
        conf = "NONE"
        try:
            pj = r.filter_results["pi_and_jailbreak"].pi_and_jailbreak_filter_result
            if pj.match_state == m.FilterMatchState.MATCH_FOUND:
                lvl = m.DetectionConfidenceLevel(pj.confidence_level).name  # LOW_AND_ABOVE / MEDIUM_AND_ABOVE / HIGH
                conf = {"LOW_AND_ABOVE": "LOW", "MEDIUM_AND_ABOVE": "MEDIUM", "HIGH": "HIGH"}.get(lvl, "MEDIUM")
                signals.append(f"model armor pi_and_jailbreak {lvl}")
        except Exception:  # noqa: BLE001
            pass
        try:
            mu = r.filter_results["malicious_uris"].malicious_uri_filter_result
            if mu.match_state == m.FilterMatchState.MATCH_FOUND:
                signals.append("model armor malicious URI")
                conf = "HIGH" if CONF_ORDER[conf] < 3 else conf
        except Exception:  # noqa: BLE001
            pass
        return {"provider": self.name, "match": conf != "NONE", "confidence": conf, "signals": signals, "addressed_to_guard": False, "excerpts": []}


class CombinedScreener:
    def __init__(self, screeners: list[Any], pool: Any = None):
        self.screeners = screeners
        self.pool = pool  # optional executor: every (page, screener) pair runs at once, so Model Armor calls don't queue

    def screen_pages(self, pages: list[Any]) -> dict[str, Any]:
        out = {"provider": " + ".join(s.name for s in self.screeners), "match": False, "confidence": "NONE",
               "signals": [], "addressed_to_guard": False, "pages_screened": 0, "excerpts": [], "by_provider": {}}
        texts = [(getattr(p, "content", None) if not isinstance(p, dict) else p.get("content", "")) or "" for p in pages]
        if self.pool is not None:
            futs = [[self.pool.submit(s.screen, t) for s in self.screeners] for t in texts]
            results = [[f.result() for f in row] for row in futs]
        else:
            results = [[s.screen(t) for s in self.screeners] for t in texts]
        for p, row in zip(pages, results):
            url = getattr(p, "url", None) if not isinstance(p, dict) else p.get("url", "")
            out["pages_screened"] += 1
            for s, r in zip(self.screeners, row):
                if CONF_ORDER[r["confidence"]] > CONF_ORDER[out["confidence"]]:
                    out["confidence"] = r["confidence"]
                out["match"] = out["match"] or r["match"]
                out["addressed_to_guard"] = out["addressed_to_guard"] or r.get("addressed_to_guard", False)
                out["signals"].extend(f"[{s.name}] {url}: {sig}" for sig in r["signals"])
                prev = out["by_provider"].get(s.name, "NONE")
                if CONF_ORDER[r["confidence"]] >= CONF_ORDER[prev]:
                    out["by_provider"][s.name] = r["confidence"]
                for ex in r.get("excerpts", []):
                    item = {"url": url, **ex}
                    if item not in out["excerpts"]:
                        out["excerpts"].append(item)
        out["signals"] = out["signals"][:20]
        out["excerpts"] = out["excerpts"][:8]
        return out


def datamark(text: str, marker: str = "^") -> str:
    """Spotlighting (Hines et al. 2024): interleave a marker between words so the model can
    tell data from instructions. Used only for the Gemini stage-2 page screen."""
    return marker.join((text or "").split())
