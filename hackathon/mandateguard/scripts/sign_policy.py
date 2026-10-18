"""Sign the policy packs as their approver, offline. Writes src/mandateguard/packs/approvals.json.

  python scripts/sign_policy.py                       # uses the demo approver key in .demo/keys.json (created if missing)
  python scripts/sign_policy.py --approver head-of-payments-risk --approved-at 2026-10-14

Run it after every pack change, then deploy. MandateGuard verifies each signature against the approver key the operator
registered (POST /v1/admin/policy-approvers). With MG_REQUIRE_POLICY_APPROVAL=1, an unsigned or edited pack blocks every
purchase until it is signed again.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from jwcrypto.jwk import JWK  # noqa: E402

from mandateguard import policy_approval  # noqa: E402
from mandateguard.rules.engine import PackStore  # noqa: E402

KEYS = ROOT / ".demo" / "keys.json"
PACKS = ROOT / "src" / "mandateguard" / "packs"


def approver_key() -> JWK:
    keys = json.loads(KEYS.read_text()) if KEYS.exists() else {}
    if "approver" not in keys:
        k = JWK.generate(kty="EC", crv="P-256", kid="risk-approver-1")
        keys["approver"] = k.export()
        KEYS.parent.mkdir(exist_ok=True)
        KEYS.write_text(json.dumps(keys))
    return JWK.from_json(keys["approver"])


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--approver", default="head-of-payments-risk")
    ap.add_argument("--approved-at", default=time.strftime("%Y-%m-%d"))
    a = ap.parse_args()
    key = approver_key()
    entries = []
    for p in PackStore(str(PACKS)).packs:
        if p.approved_by and p.approved_by != a.approver:
            raise SystemExit(f"{p.name} names {p.approved_by} as its approver, not {a.approver}")
        st = policy_approval.statement(p.name, p.version, p.file_sha256, a.approver, a.approved_at)
        entries.append({k: st[k] for k in ("pack", "version", "file_sha256", "approved_by", "approved_at")} | {"signature": policy_approval.sign(st, key)})
        print(f"signed {p.name} v{p.version}  {p.file_sha256[:16]}…")
    (PACKS / policy_approval.APPROVALS_FILE).write_text(json.dumps({"approvals": entries}, indent=2) + "\n")
    print(f"wrote {PACKS / policy_approval.APPROVALS_FILE}; approver public key thumbprint {key.thumbprint()}")


if __name__ == "__main__":
    main()
