"""MandateGuard: governance service for AP2 agent payments.

Pipeline (locked architecture):
  stage 0  input guardrails      -> schema, size limits, tool allow-list, pages are data
  stage 1  YAML rule packs (CEL) -> ALLOW / ESCALATE / DENY, DENY is final
  stage 2  Gemini checks         -> may only tighten (ESCALATE / DENY), never ALLOW
  stage 3  decision record       -> signed, hash-chained; token requested only on ALLOW
"""

__version__ = "0.3.0"
