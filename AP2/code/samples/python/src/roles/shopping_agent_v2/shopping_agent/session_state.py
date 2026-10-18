"""Per-chat state keys.

The A2A executor opens a new ADK session for every message (session id = A2A
context id, which the web app and the Telegram bot do not send), so state that
must survive between turns lives in ``app:`` state, which ADK shares across ALL
sessions and users. Scoping each key by the client's stable ``sessionId``
(A2A request metadata) keeps one chat's mandate, plan, trace and pages from
leaking into another's.
"""

import re
from typing import Any


def chat_id(ctx: Any) -> str:
  """The client's stable chat id (A2A ``metadata.sessionId``), or ``default``."""
  try:
    meta = (ctx.run_config.custom_metadata or {}).get("a2a_metadata") or {}
    sid = str(meta.get("sessionId") or "")
  except AttributeError:
    sid = ""
  return re.sub(r"[^A-Za-z0-9_-]", "", sid)[:64] or "default"


def skey(ctx: Any, name: str) -> str:
  """``app:`` state key for ``name`` scoped to this chat."""
  return f"app:{chat_id(ctx)}:{name}"
