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
    assert "高危破坏性操作" in out["permissionDecisionReason"]


def test_destructive_restore_command():
    payload = json.dumps({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "git restore ."},
    })
    resp = handle_hook_input(payload, mock=True)
    out = resp["hookSpecificOutput"]
    assert out["permissionDecision"] == "deny"
    assert "高危破坏性操作" in out["permissionDecisionReason"]


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
    assert "高危破坏性操作" in out["permissionDecisionReason"]


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
    assert "高危破坏性操作" in out["permissionDecisionReason"]


def test_commit_mentioning_dangerous_word_allowed():
    payload = json.dumps({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "git commit -m 'fix bug caused by rm -rf in build script'"},
    })
    resp = handle_hook_input(payload, mock=True)
    out = resp["hookSpecificOutput"]
    assert out["permissionDecision"] == "allow"


def test_test_runner_command_with_dangerous_keywords_allowed():
    payload = json.dumps({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "uv run pytest -k 'test_destructive_reset_command'"},
    })
    resp = handle_hook_input(payload, mock=True)
    out = resp["hookSpecificOutput"]
    assert out["permissionDecision"] == "allow"


def test_code_edit_containing_dangerous_command_string_allowed():
    payload = json.dumps({
        "hook_event_name": "PreToolUse",
        "tool_name": "Edit",
        "tool_input": {
            "file_path": "tests/test_guard.py",
            "old_string": "foo",
            "new_string": "subprocess.run(['rm', '-rf', tmp_dir])",
        },
    })
    resp = handle_hook_input(payload, mock=True)
    out = resp["hookSpecificOutput"]
    assert out["permissionDecision"] == "allow"


def test_direct_rm_rf_command_denied():
    payload = json.dumps({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "rm -rf /var/data"},
    })
    resp = handle_hook_input(payload, mock=True)
    out = resp["hookSpecificOutput"]
    assert out["permissionDecision"] == "deny"
    assert "高危破坏性操作" in out["permissionDecisionReason"]


def test_unconfigured_api_key_failsafe():
    payload = json.dumps({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "git status"},
    })
    resp = handle_hook_input(payload, api_key="", mock=False)
    out = resp["hookSpecificOutput"]
    assert out["permissionDecision"] == "deny"
    assert "未配置 TYPESAFE_API_KEY" in out["permissionDecisionReason"]


def test_invalid_json_payload():
    resp = handle_hook_input("invalid json {{{")
    out = resp["hookSpecificOutput"]
    assert out["permissionDecision"] == "deny"
    assert "无效的 JSON" in out["permissionDecisionReason"]
