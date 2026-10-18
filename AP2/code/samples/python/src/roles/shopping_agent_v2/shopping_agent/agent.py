"""Shopping Agent: Sub-agent hierarchy.

The hierarchy consists of consent_agent → monitoring_agent → purchase_agent.
Root agent is consent_agent; it transfers to monitoring_agent after mandate
approval. monitoring_agent transfers to purchase_agent when price constraint is
met.

The agent reaches the merchant, credentials provider and payment processor as
separate A2A HTTP services via the tools in ``a2a_tools`` (no in-process MCP).
Local mandate signing/verification stays in ``mandate_tools``; payment-credential
issuance is gated by MandateGuard (see ``_mandate_guard_before_tool_callback``).
"""

import asyncio
import json
import logging
import os

from pathlib import Path
from typing import Any

from google.adk.agents import Agent
from google.adk.tools.base_tool import BaseTool
from google.adk.tools.tool_context import ToolContext
from google.genai import types

from shopping_agent import a2a_tools, mandate_guard
from shopping_agent.session_state import skey
from shopping_agent.mandate_tools import (
  assemble_and_sign_mandates_tool as _sign_mandates,
  check_constraints_against_mandate,
  create_checkout_presentation,
  create_payment_presentation,
)


_AGENT_DIR = Path(__file__).resolve().parent
_AP2_ROOT = _AGENT_DIR.parent.parent
_LOG_DIR = Path(os.environ.get("LOGS_DIR", _AP2_ROOT / ".logs"))
_LOG_FILE = _LOG_DIR / "shopping-agent.log"
_LOG_DIR.mkdir(parents=True, exist_ok=True)

_shopping_logger = logging.getLogger("shopping_agent")
_shopping_logger.setLevel(logging.DEBUG)
if not _shopping_logger.handlers:
  _fh = logging.FileHandler(_LOG_FILE, mode="w", encoding="utf-8")
  _fh.setFormatter(
      logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
  )
  _shopping_logger.addHandler(_fh)
  # Also to stderr, so Cloud Run's logging captures the agent's decisions.
  _sh = logging.StreamHandler()
  _sh.setFormatter(logging.Formatter("shopping_agent %(levelname)s %(message)s"))
  _shopping_logger.addHandler(_sh)

_PROMPTS_DIR = _AGENT_DIR / "prompts"


def _error_escalation_callback(
    tool: BaseTool,
    args: dict[str, Any],
    tool_context: ToolContext,
    tool_response: dict[str, Any],
) -> dict[str, str] | None:
  """Intercept MCP tool errors and reformat them so the LLM reliably emits.

  a structured error artifact instead of mangling or ignoring the error.

  Args:
      tool: The tool that was executed.
      args: The arguments passed to the tool.
      tool_context: The context of the tool execution.
      tool_response: The response from the tool.

  Returns:
      A dictionary containing error details and an action message if an error
      is present in `tool_response`, otherwise None.
  """
  if isinstance(tool_response, dict) and "error" in tool_response:
    code = tool_response["error"]
    msg = tool_response.get("message", str(tool_response))
    tool_name = getattr(tool, "name", str(tool))
    _shopping_logger.warning(
        "Tool %s returned error: %s – %s",
        tool_name,
        code,
        msg,
    )
    error_json = json.dumps(
        {"type": "error", "error": code, "message": msg},
        ensure_ascii=True,
    )
    return {
        "error": code,
        "message": msg,
        "action_required": (
            "STOP all processing. Emit EXACTLY this JSON as your"
            f" complete response, nothing else: {error_json}"
        ),
    }
  return None


# Tools whose calls are recorded in the MandateGuard decision trace. The gate is
# no longer a before-tool check on issue_payment_credential; the purchase agent
# calls MandateGuard's /v1/decisions directly (request_mandateguard_decision),
# which replaces issue_payment_credential entirely.
_TRACED_TOOLS = {
    "check_product",
    "read_product_page",
    "assemble_cart",
    "create_checkout",
    "create_payment_presentation",
    "create_checkout_presentation",
}


def _trace_before_tool_callback(
    tool: BaseTool,
    args: dict[str, Any],
    tool_context: ToolContext,
) -> dict[str, str] | None:
  """Record each purchase-agent tool call in the MandateGuard decision trace.

  MandateGuard screens the trace for drift and injected instructions. The trace
  is kept in session state and sent with the /v1/decisions request. This never
  blocks a tool (always returns None).
  """
  name = getattr(tool, "name", "")
  if name in _TRACED_TOOLS:
    try:
      trace = tool_context.state.get(skey(tool_context, "mg_trace")) or []
      trace.append({
          "seq": len(trace) + 1,
          "kind": "tool_call",
          "tool": name,
          "data": {k: v for k, v in (args or {}).items()
                   if isinstance(v, (str, int, float, bool))},
      })
      tool_context.state[skey(tool_context, "mg_trace")] = trace
    except Exception:  # pylint: disable=broad-exception-caught
      pass
  return None


def _monitoring_after_tool_callback(
    tool: BaseTool,
    args: dict[str, Any],
    tool_context: ToolContext,
    tool_response: dict[str, Any],
) -> dict[str, str] | None:
  """Deterministically hand off monitoring -> purchase.

  Relying on the model to call transfer_to_agent is unreliable. Instead, the
  moment check_constraints_against_mandate reports the mandate is met AND the
  item is available at a real (non-zero) price, we force the transfer via ADK's
  transfer action. The price > 0 guard skips the initial price=0 extraction call.
  """
  esc = _error_escalation_callback(tool, args, tool_context, tool_response)
  if esc is not None:
    return esc
  if (
      getattr(tool, "name", "") == "check_constraints_against_mandate"
      and isinstance(tool_response, dict)
      and tool_response.get("meets_constraints")
      and tool_response.get("available")
      and (tool_response.get("price") or 0) > 0
  ):
    _commit_mandateguard_plan(tool_context, tool_response)
    _shopping_logger.info(
        "Constraints met at price=%s; transferring to purchase_agent.",
        tool_response.get("price"),
    )
    tool_context.actions.transfer_to_agent = "purchase_agent"
  return None


def _commit_mandateguard_plan(
    tool_context: ToolContext, constraints: dict[str, Any]
) -> None:
  """Commit the plan with MandateGuard before the purchase agent reads any page.

  Fixes the intended items + payee with MandateGuard's own clock and signature;
  later steps are compared against it. No-op when MandateGuard is not configured
  or the plan was already committed this session.
  """
  if not os.environ.get("MANDATE_GUARD_URL"):
    return
  state = tool_context.state
  mandate_id = state.get(skey(tool_context, "mg_mandate_id"), "")
  if not mandate_id:
    return
  # Re-commit when the mandate changed; a stale plan from a prior order would
  # mismatch the current mandate at decision time (MandateGuard denies).
  if state.get(skey(tool_context, "mg_plan_id")) and state.get(skey(tool_context, "mg_plan_for")) == mandate_id:
    return
  try:
    line_items = constraints.get("line_items") or []
    first = (line_items[0] if line_items else {}) or {}
    acceptable = first.get("acceptable_items") or []
    sku = acceptable[0]["id"] if acceptable else ""
    qty = int(first.get("quantity", 1))
    items = [{"sku": sku, "qty": qty}] if sku else []
    plan = mandate_guard.commit_plan(
        mandate_id, items, os.environ.get("MG_MERCHANT_ID", "merchant_1")
    )
    state[skey(tool_context, "mg_plan_id")] = plan.get("plan_id", "")
    state[skey(tool_context, "mg_plan_for")] = mandate_id
    trace = state.get(skey(tool_context, "mg_trace")) or []
    trace.append({"seq": len(trace) + 1, "kind": "plan", "summary": "Price alert",
                  "data": {"items": items,
                           "payee_id": os.environ.get("MG_MERCHANT_ID", "merchant_1")}})
    state[skey(tool_context, "mg_trace")] = trace
    _shopping_logger.info("MandateGuard plan committed: %s", plan.get("plan_id"))
  except Exception as e:  # pylint: disable=broad-exception-caught
    _shopping_logger.error("MandateGuard commit_plan failed: %s", e)


_DATA_START, _DATA_END = b"<a2a_datapart_json>", b"</a2a_datapart_json>"


def _approved_mandate(tool_context: ToolContext) -> dict[str, Any] | None:
  """The mandate_request the user approved on the approval card, if this turn carries one.

  Only the client's ``mandate_approved`` data part (the approval button) counts;
  typed text such as "yes" never does. ADK delivers A2A data parts as tagged
  inline_data in the invocation's user content.
  """
  content = getattr(tool_context, "user_content", None)
  for part in getattr(content, "parts", None) or []:
    blob = getattr(part, "inline_data", None)
    raw = getattr(blob, "data", None) or b""
    if not (raw.startswith(_DATA_START) and raw.endswith(_DATA_END)):
      continue
    try:
      data = json.loads(raw[len(_DATA_START):-len(_DATA_END)]).get("data") or {}
    except (ValueError, AttributeError):
      continue
    if data.get("type") == "mandate_approved" and isinstance(data.get("mandate_request"), dict):
      return data["mandate_request"]
  return None


async def assemble_and_sign_mandates_tool(
    mandate_request: str,
    tool_context: ToolContext,
) -> dict[str, Any]:
  """ADK tool to assemble and sign open mandates as SD-JWTs.

  This function parses the JSON request, generates the mandates, and persists
  them to the session state (`tool_context.state`). Constraints can be checked
  later using `check_constraints_against_mandate`.

  Args:
      mandate_request: A JSON string containing mandate details (item_id,
        price_cap, etc.).
      tool_context: The ADK ToolContext (automatically injected).

  Returns:
      A dictionary containing the "open_checkout_mandate" and
      "open_payment_mandate" ids, or a dictionary with an "error" key if the
      operation fails.
  """
  # Sign only what the user approved on the approval card, exactly as approved,
  # and at most once per approval: the model's own arguments are never signed.
  approved = _approved_mandate(tool_context)
  if approved is None:
    _shopping_logger.warning("signing refused: no mandate_approved in this turn")
    return {"status": "approval_required",
            "message": "Not signed. The user has not approved a mandate on the approval"
                       " card. Emit the mandate_request JSON and wait for mandate_approved."}
  if tool_context.state.get("temp:mandate_signed"):
    return {"status": "already_signed",
            "message": "This approval was already signed. Hand off to monitoring."}
  tool_context.state["temp:mandate_signed"] = True
  mandate_request = json.dumps(approved)
  # Signing and MandateGuard registration block on HTTP; keep the loop free.
  result = await asyncio.to_thread(_sign_mandates, mandate_request, tool_context)
  if "error" in result:
    return result
  # Demo: if the item is not in stock within budget, the merchant schedules a
  # price drop under the budget that goes live within 0-30s, so every signed
  # order completes. Never fails the signing.
  try:
    req = json.loads(mandate_request) if isinstance(mandate_request, str) else mandate_request
    result["demo_drop"] = await a2a_tools.prepare_drop(
        item_id=req["item_id"],
        price_cap=float(req["price_cap"]),
        qty=int(req.get("qty") or 1),
        name=req.get("item_name") or "",
    )
  except Exception as e:  # pylint: disable=broad-exception-caught
    _shopping_logger.warning("demo price drop not scheduled: %s", e)
  return result


def reset_temp_db() -> dict[str, str]:
  """Cleans up mandate files in the .temp-db directory.

  Use this tool when you want to start or restart the flow with a clean state.
  It preserves server keys.
  """
  try:
    temp_db_dir = Path(os.environ.get("TEMP_DB_DIR", _AP2_ROOT / ".temp-db"))
    if temp_db_dir.exists():
      prefixes = ["chk_", "open_chk_", "pay_", "open_pay_"]
      count = 0
      for item in temp_db_dir.iterdir():
        if item.is_file():
          if any(item.name.startswith(prefix) for prefix in prefixes):
            item.unlink()
            count += 1
      return {
          "status": "ok",
          "message": f"Removed {count} mandate files from {temp_db_dir}",
      }
    return {"status": "ok", "message": f"No temp DB found at {temp_db_dir}"}
  except Exception as e:
    return {"error": "reset_failed", "message": str(e)}


_CONSENT_INSTRUCTION = (_PROMPTS_DIR / "consent_agent.md").read_text()
_MONITORING_INSTRUCTION = (_PROMPTS_DIR / "monitoring_agent.md").read_text()
_PURCHASE_INSTRUCTION = (_PROMPTS_DIR / "purchase_agent.md").read_text()

_model = os.environ.get("AGENT_MODEL", "gemini-3.1-flash-lite-preview")

# Disable model "thinking" — it adds ~1s+ to every call and this flow is
# tool-driven, not reasoning-heavy. Big latency win across the many turns.
_GEN_CONFIG = types.GenerateContentConfig(
    temperature=0,
    thinking_config=types.ThinkingConfig(thinking_budget=0),
)
# The consent agent decides when to emit mandate_request; a little thinking and
# temperature 0 keep it from skipping the request or claiming a mandate it never asked for.
_CONSENT_GEN_CONFIG = types.GenerateContentConfig(
    temperature=0,
    thinking_config=types.ThinkingConfig(thinking_budget=1024),
)

purchase_agent = Agent(
    name="purchase_agent",
    model=_model,
    generate_content_config=_GEN_CONFIG,
    description=(
        "Executes the autonomous purchase flow when price and availability"
        " satisfy the open mandates: assemble_cart, create_checkout, closed"
        " mandates, then MandateGuard decides and charges"
        " (request_mandateguard_decision)."
    ),
    instruction=_PURCHASE_INSTRUCTION,
    output_key="purchase_result",
    tools=[
        check_constraints_against_mandate,
        create_checkout_presentation,
        create_payment_presentation,
        a2a_tools.check_product,
        a2a_tools.read_product_page,
        a2a_tools.assemble_cart,
        a2a_tools.create_checkout,
        a2a_tools.request_mandateguard_decision,
    ],
    before_tool_callback=_trace_before_tool_callback,
    after_tool_callback=_error_escalation_callback,
)

monitoring_agent = Agent(
    name="monitoring_agent",
    model=_model,
    generate_content_config=_GEN_CONFIG,
    description=(
        "Holds open mandates and monitors item price and availability via"
        " check_product. Transfers to purchase_agent when price is within the"
        " mandate and the merchant reports the item as available."
    ),
    instruction=_MONITORING_INSTRUCTION,
    output_key="monitoring_result",
    tools=[
        check_constraints_against_mandate,
        a2a_tools.check_product,
        a2a_tools.read_product_page,
    ],
    sub_agents=[purchase_agent],
    after_tool_callback=_monitoring_after_tool_callback,
)

consent_agent = Agent(
    name="consent_agent",
    model=_model,
    generate_content_config=_CONSENT_GEN_CONFIG,
    description=(
        "Handles drop/budget dialogue, product search, item selection, and"
        " open-mandate signing. Transfers to monitoring_agent after"
        " mandate_approved or on 'Check price now'."
    ),
    instruction=_CONSENT_INSTRUCTION,
    output_key="consent_result",
    tools=[
        reset_temp_db,
        a2a_tools.search_products,
        a2a_tools.seed_product,
        assemble_and_sign_mandates_tool,
        a2a_tools.check_product,
    ],
    sub_agents=[monitoring_agent],
    after_tool_callback=_error_escalation_callback,
)

root_agent = consent_agent
