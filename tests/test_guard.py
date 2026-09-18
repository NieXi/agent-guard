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
    assert "拦截" in out["permissionDecisionReason"]


def test_destructive_restore_command():
    payload = json.dumps({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "git restore ."},
    })
    resp = handle_hook_input(payload, mock=True)
    out = resp["hookSpecificOutput"]
    assert out["permissionDecision"] == "deny"
    assert "拦截" in out["permissionDecisionReason"]


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
    assert "拦截" in out["permissionDecisionReason"]


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
    assert "拦截" in out["permissionDecisionReason"]


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
    assert "拦截" in out["permissionDecisionReason"]


def test_unconfigured_api_key_failsafe(monkeypatch):
    monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)
    # Ensure no rc file is detected in current dir
    from agent_guard import config
    monkeypatch.setattr(config, "load_config", lambda: {})

    payload = json.dumps({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "git status"},
    })
    resp = handle_hook_input(payload, api_key="", mock=False)
    out = resp["hookSpecificOutput"]
    assert out["permissionDecision"] == "deny"
    assert "未检测到 TYPESAFE_API_KEY" in out["permissionDecisionReason"]


def test_invalid_json_payload():
    resp = handle_hook_input("invalid json {{{")
    out = resp["hookSpecificOutput"]
    assert out["permissionDecision"] == "deny"
    assert "无效的 JSON" in out["permissionDecisionReason"]


def test_safe_internal_tools_bypassed():
    for safe_tool in ["TaskCreate", "TaskUpdate", "AskUserQuestion", "Read", "Grep", "ToolSearch"]:
        payload = json.dumps({
            "hook_event_name": "PreToolUse",
            "tool_name": safe_tool,
            "tool_input": {"description": "准备执行数据库清理", "prompt": "清理过期备份"},
        })
        # Even without API Key, these should be 0ms allowed without calling network
        resp = handle_hook_input(payload, api_key="", mock=False)
        out = resp["hookSpecificOutput"]
        assert out["permissionDecision"] == "allow"
        assert "无害任务调度" in out["permissionDecisionReason"]


def test_load_key_from_rc_content(tmp_path, monkeypatch):
    monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)
    rc_file = tmp_path / ".agentguardrc"
    rc_file.write_text("# Config\nTYPESAFE_API_KEY=test_rc_key_12345\n", encoding="utf-8")

    from agent_guard import config
    monkeypatch.setattr(config, "find_rc_file", lambda: rc_file)

    client = GuardClient(api_key=None)
    assert client.api_key == "test_rc_key_12345"
