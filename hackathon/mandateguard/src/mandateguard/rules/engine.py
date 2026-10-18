"""YAML rule packs with CEL (Common Expression Language) conditions.

Pack format::

    pack: mandate
    version: 2
    rules:
      - id: mandate.price_out_of_range
        title: Price outside the signed range          # short label shown in the console
        outcome: DENY                                  # ALLOW | ESCALATE | DENY
        rank: 25                                       # lower = more important when choosing the headline
        source: AP2 SDK                                # optional; default "Policy · <pack> v<version>"
        when: "cart.total_minor > mandate.max_minor"   # CEL
        detail: "cart.total_minor"                     # optional CEL, available to the reason as {detail}
        reason: "The cart total is {cart.total_minor|money}. ..."   # template, see render.py

Semantics (fail closed): every rule of every pack runs against the same facts; DENY > ESCALATE > ALLOW;
no ALLOW rule fired => DENY ("default deny"); a rule that errors => DENY. Packs hot-reload, and
packs_hash (sha256 over the files) is written into every decision record.
"""

from __future__ import annotations

import glob
import hashlib
import os
from dataclasses import dataclass, field
from typing import Any

import celpy
import yaml
from celpy import celtypes

from ..models import Finding, Stage, Verdict
from .render import render


@dataclass
class CompiledRule:
    pack: str
    id: str
    outcome: Verdict
    when: str
    title: str
    reason: str
    rank: int
    source: str
    program: Any
    detail_program: Any | None = None


@dataclass
class CompiledPack:
    name: str
    version: str
    path: str
    rules: list[CompiledRule] = field(default_factory=list)
    owner: str = ""
    approved_by: str = ""
    effective: str = ""
    file_sha256: str = ""
    raw: bytes = b""


@dataclass
class RuleResult:
    verdict: Verdict
    findings: list[Finding]
    fired: list[dict[str, Any]]
    errors: list[dict[str, Any]]
    packs_hash: str
    default_deny: bool
    evaluated: int = 0
    passed: int = 0
    packs: list[dict[str, str]] = field(default_factory=list)


class PackStore:
    def __init__(self, directory: str):
        self.dir = directory
        self.mtimes: dict[str, float] = {}
        self.packs: list[CompiledPack] = []
        self.packs_hash = ""
        self.env = celpy.Environment()
        self.maybe_reload()

    def maybe_reload(self) -> None:
        files = sorted(glob.glob(os.path.join(self.dir, "*.yaml")) + glob.glob(os.path.join(self.dir, "*.yml")))
        cur = {f: os.path.getmtime(f) for f in files}
        if cur != self.mtimes:
            self.mtimes = cur
            self.packs = [self._compile(f) for f in files]
            h = hashlib.sha256()
            for f in files:
                with open(f, "rb") as fh:
                    h.update(os.path.basename(f).encode())
                    h.update(fh.read())
            self.packs_hash = h.hexdigest()

    def _compile(self, path: str) -> CompiledPack:
        with open(path, "rb") as fh:
            raw = fh.read()
        doc = yaml.safe_load(raw.decode("utf-8")) or {}
        pack = CompiledPack(name=str(doc.get("pack", os.path.basename(path))), version=str(doc.get("version", "1")), path=path,
                            owner=str(doc.get("owner", "")), approved_by=str(doc.get("approved_by", "")), effective=str(doc.get("effective", "")),
                            file_sha256=hashlib.sha256(raw).hexdigest(), raw=raw)
        default_source = f"Policy · {pack.name} v{pack.version}"
        for r in doc.get("rules", []) or []:
            prog = self.env.program(self.env.compile(str(r["when"])))
            detail_prog = self.env.program(self.env.compile(str(r["detail"]))) if r.get("detail") else None
            pack.rules.append(CompiledRule(
                pack=pack.name, id=str(r["id"]), outcome=Verdict(str(r["outcome"]).upper()), when=str(r["when"]),
                title=str(r.get("title", r["id"])), reason=str(r.get("reason", r.get("title", r["id"]))),
                rank=int(r.get("rank", 50)), source=str(r.get("source", default_source)), program=prog, detail_program=detail_prog,
            ))
        return pack


def _to_python(value: Any) -> Any:
    if isinstance(value, celtypes.MapType):
        return {str(k): _to_python(v) for k, v in value.items()}
    if isinstance(value, celtypes.ListType):
        return [_to_python(v) for v in value]
    if isinstance(value, celtypes.BoolType):
        return bool(value)
    if isinstance(value, (celtypes.IntType, celtypes.UintType)):
        return int(value)
    if isinstance(value, celtypes.DoubleType):
        return float(value)
    if isinstance(value, celtypes.StringType):
        return str(value)
    return str(value)


def evaluate(store: PackStore, facts: dict[str, Any]) -> RuleResult:
    store.maybe_reload()
    activation = celpy.json_to_cel(facts)
    fired: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    findings: list[Finding] = []
    evaluated = 0
    checks_passed = 0
    for pack in store.packs:
        for r in pack.rules:
            evaluated += 1
            try:
                hit = r.program.evaluate(activation) == celtypes.BoolType(True)
            except Exception as e:  # noqa: BLE001 - fail closed
                errors.append({"pack": pack.name, "rule": r.id, "error": f"{type(e).__name__}: {e}"})
                findings.append(Finding(stage=Stage.S1, code="rule_error", outcome=Verdict.DENY, title="Policy rule failed to run",
                                        message=f"Rule {r.id} could not be evaluated, so the decision fails closed.",
                                        detail=str(e), pack=pack.name, rule=r.id, rank=7, source=r.source))
                continue
            if not hit:
                if r.outcome != Verdict.ALLOW:
                    checks_passed += 1
                continue
            detail = None
            if r.detail_program is not None:
                try:
                    detail = _to_python(r.detail_program.evaluate(activation))
                except Exception as e:  # noqa: BLE001
                    detail = f"detail error: {e}"
            try:
                message = render(r.reason, facts, detail)
            except Exception:  # noqa: BLE001 - never let wording break a decision
                message = r.title
            fired.append({"pack": pack.name, "rule": r.id, "outcome": r.outcome.value, "reason": message, "detail": detail})
            findings.append(Finding(stage=Stage.S1, code=r.id, outcome=r.outcome, title=r.title, message=message, detail=detail,
                                    pack=pack.name, rule=r.id, rank=r.rank, source=r.source))
    outcomes = {f["outcome"] for f in fired}
    if errors or "DENY" in outcomes:
        verdict = Verdict.DENY
    elif "ESCALATE" in outcomes:
        verdict = Verdict.ESCALATE
    elif "ALLOW" in outcomes:
        verdict = Verdict.ALLOW
    else:
        verdict = Verdict.DENY
    default_deny = verdict == Verdict.DENY and not errors and "DENY" not in outcomes
    if default_deny:
        findings.append(Finding(stage=Stage.S1, code="default_deny", outcome=Verdict.DENY, title="No rule allowed this purchase",
                                message="No policy rule confirmed the purchase is within the mandate, so it is blocked by default.", rank=60))
    return RuleResult(verdict=verdict, findings=findings, fired=fired, errors=errors, packs_hash=store.packs_hash,
                      default_deny=default_deny, evaluated=evaluated, passed=checks_passed,
                      packs=[{"name": p.name, "version": p.version, "owner": p.owner, "approved_by": p.approved_by} for p in store.packs])
