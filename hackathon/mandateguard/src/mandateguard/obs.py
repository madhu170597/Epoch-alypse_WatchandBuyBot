"""Operational events: one JSON line per event on stdout.

Cloud Run turns each line into a log entry with `jsonPayload`, so log-based metrics and alert policies can select on
`jsonPayload.event`. The signed chain remains the record of what happened; these lines are for watching it happen:
decisions, receipts and deliveries that don't match, a chain that fails verification, a checkpoint that wasn't written.
Set MG_OBS_LOG=0 to silence them.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any


def emit(event: str, severity: str = "INFO", **fields: Any) -> None:
    if os.environ.get("MG_OBS_LOG", "1") == "0":
        return
    line = {"severity": severity, "event": event, "message": str(fields.pop("message", event)), **fields}
    try:
        sys.stdout.write(json.dumps(line, default=str) + "\n")
        sys.stdout.flush()
    except Exception:  # noqa: BLE001 - observability never breaks a decision
        pass
