"""Claude Code PreToolUse Hook Handler.

Inspects incoming tool calls from Claude Code via stdin, evaluates them
using TypeSafe System One against safety and policy rules, and returns
the official Claude Code hook response format to stdout.
"""

import json
import os
import sys
from typing import Any, Dict, Optional
from agent_guard.client import GuardClient


def handle_hook_input(
    payload_json: str,
    api_key: Optional[str] = None,
    mock: bool = False,
    audit_log: Optional[str] = None,
) -> Dict[str, Any]:
    """Process a raw JSON payload from Claude Code's PreToolUse hook.

    Args:
        payload_json: The raw JSON string from stdin.
        api_key: Optional TypeSafe API Key override.
        mock: Force mock/heuristic mode without calling network.
        audit_log: Optional file path to append audit log entries.

    Returns:
        The official Claude Code hook response dictionary.
    """
    try:
        data = json.loads(payload_json)
    except json.JSONDecodeError as e:
        # If payload is invalid JSON, fail safe by denying or reporting error
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": f"PreToolUse Hook 收到无效的 JSON 输入: {e}",
            }
        }

    tool_name = data.get("tool_name", "UnknownTool")
    tool_input = data.get("tool_input", {})
    cwd = data.get("cwd", os.getcwd())
    session_id = data.get("session_id", "")
    tool_use_id = data.get("tool_use_id", "")

    # Evaluate via GuardClient
    client = GuardClient(api_key=api_key)
    eval_result = client.evaluate_tool_call(
        tool_name=tool_name,
        tool_input=tool_input,
        cwd=cwd,
        mock=mock,
    )

    decision = eval_result.get("decision", "allow")
    reason = eval_result.get("reason", "通过安全评估")
    scores = eval_result.get("scores", {})

    # Map internal decision to official Claude Code permissionDecision
    # Claude Code accepts: "allow", "deny", "ask"
    permission_decision = decision

    hook_response = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": permission_decision,
            "permissionDecisionReason": f"[TypeSafe Guard] {reason}",
        }
    }

    # Optional Audit Logging
    log_path = audit_log or os.getenv("AGENT_GUARD_LOG")
    if log_path:
        _write_audit_log(
            log_path=log_path,
            session_id=session_id,
            tool_name=tool_name,
            tool_input=tool_input,
            decision=permission_decision,
            reason=reason,
            scores=scores,
        )

    return hook_response


def _write_audit_log(
    log_path: str,
    session_id: str,
    tool_name: str,
    tool_input: Any,
    decision: str,
    reason: str,
    scores: Dict[str, Any],
):
    """Write an audit entry in JSONL format."""
    import time

    entry = {
        "timestamp": time.time(),
        "time_str": time.strftime("%Y-%m-%d %H:%M:%S"),
        "session_id": session_id,
        "tool_name": tool_name,
        "tool_input": tool_input,
        "decision": decision,
        "reason": reason,
        "scores": scores,
    }
    try:
        os.makedirs(os.path.dirname(os.path.abspath(log_path)), exist_ok=True)
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception:
        pass  # Never let audit log failure break the hook flow
