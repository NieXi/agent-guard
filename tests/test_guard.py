"""Unit tests for agent_guard."""

import json
from agent_guard.guard import handle_hook_input
from agent_guard.client import GuardClient


def test_safe_read_command():
    payload = json.dumps({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "git status"},
    })
    resp = handle_hook_input(payload, mock=True)
    out = resp["hookSpecificOutput"]
    assert out["permissionDecision"] == "allow"
    assert "通过" in out["permissionDecisionReason"] or "无高危" in out["permissionDecisionReason"]


def test_destructive_reset_command():
    payload = json.dumps({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "git reset --hard origin/master"},
    })
    resp = handle_hook_input(payload, mock=True)
    out = resp["hookSpecificOutput"]
    assert out["permissionDecision"] == "deny"
    assert "git reset --hard" in out["permissionDecisionReason"]


def test_destructive_restore_command():
    payload = json.dumps({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "git restore ."},
    })
    resp = handle_hook_input(payload, mock=True)
    out = resp["hookSpecificOutput"]
    assert out["permissionDecision"] == "deny"
    assert "git restore ." in out["permissionDecisionReason"]


def test_medium_risk_service_down():
    payload = json.dumps({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "docker compose down"},
    })
    resp = handle_hook_input(payload, mock=True)
    out = resp["hookSpecificOutput"]
    assert out["permissionDecision"] == "ask"


def test_sensitive_file_modification():
    payload = json.dumps({
        "hook_event_name": "PreToolUse",
        "tool_name": "Edit",
        "tool_input": {"file_path": "/etc/sudoers", "new_string": "foo"},
    })
    resp = handle_hook_input(payload, mock=True)
    out = resp["hookSpecificOutput"]
    assert out["permissionDecision"] == "deny"
    assert "敏感文件" in out["permissionDecisionReason"]


def test_mcp_readonly_tool():
    payload = json.dumps({
        "hook_event_name": "PreToolUse",
        "tool_name": "mcp__github__get_issue",
        "tool_input": {"issue_number": 42},
    })
    resp = handle_hook_input(payload, mock=True)
    out = resp["hookSpecificOutput"]
    assert out["permissionDecision"] == "allow"


def test_mcp_destructive_tool():
    payload = json.dumps({
        "hook_event_name": "PreToolUse",
        "tool_name": "mcp__postgres__execute_query",
        "tool_input": {"sql": "DROP TABLE users;"},
    })
    resp = handle_hook_input(payload, mock=True)
    out = resp["hookSpecificOutput"]
    assert out["permissionDecision"] == "deny"
    assert "破坏性" in out["permissionDecisionReason"]
