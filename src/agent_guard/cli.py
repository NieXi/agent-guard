"""Command Line Interface for TypeSafe Agent Tool Guard."""

import json
import os
import sys
from typing import Optional
import typer
from rich.console import Console

from agent_guard.client import GuardClient
from agent_guard.guard import handle_hook_input
from agent_guard.reporter import render_evaluation_result

app = typer.Typer(
    name="agent-guard",
    help="TypeSafe AI 驱动的 Agent 工具调用安全合规守卫，专注 Claude Code PreToolUse Hook 拦截。",
    add_completion=False,
)
console = Console()
err_console = Console(stderr=True)


@app.command(name="hook")
def hook_cmd(
    audit_log: Optional[str] = typer.Option(
        None, "--log", "-l", help="将审核记录写入指定的 JSONL 文件"
    ),
    mock: bool = typer.Option(
        False, "--mock", help="强制使用本地启发规则，不调用网络 API"
    ),
    api_key: Optional[str] = typer.Option(
        None, "--api-key", envvar="TYPESAFE_API_KEY", help="TypeSafe API Key"
    ),
):
    """Claude Code PreToolUse Hook 专用入口。

    从 stdin 读取 Claude Code 发送的 JSON 调用信息，
    向 stdout 输出官方标准格式的判定响应。
    """
    try:
        raw_input = sys.stdin.read()
        if not raw_input.strip():
            # Nothing received
            sys.exit(0)

        response = handle_hook_input(
            payload_json=raw_input,
            api_key=api_key,
            mock=mock,
            audit_log=audit_log,
        )

        # Print JSON response to stdout for Claude Code
        print(json.dumps(response, ensure_ascii=False))
        sys.stdout.flush()

        # If denied, return exit code 0 so Claude Code parses hookSpecificOutput,
        # or exit code 2 if strict blocking is desired.
        decision = response.get("hookSpecificOutput", {}).get("permissionDecision")
        if decision == "deny":
            # Exit code 0 with permissionDecision: "deny" is standard Claude Code protocol
            sys.exit(0)
        sys.exit(0)

    except Exception as e:
        err_console.print(f"[red]Hook execution error: {e}[/red]")
        # Fail safe: output deny decision so dangerous commands aren't silently executed on crash
        fallback_resp = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": f"Hook 异常保护拦截: {e}",
            }
        }
        print(json.dumps(fallback_resp, ensure_ascii=False))
        sys.exit(0)


@app.command(name="check")
def check_cmd(
    tool: str = typer.Option("Bash", "--tool", "-t", help="调用的工具名称，如 Bash, Edit, Write"),
    cmd: Optional[str] = typer.Option(None, "--cmd", "-c", help="待执行的 Bash 命令（当 tool 为 Bash 时直接使用）"),
    input_json: Optional[str] = typer.Option(None, "--input", "-i", help="工具调用的参数 (JSON 格式)"),
    mock: bool = typer.Option(False, "--mock", help="强制使用本地安全启发规则测试"),
    api_key: Optional[str] = typer.Option(None, "--api-key", envvar="TYPESAFE_API_KEY", help="TypeSafe API Key"),
):
    """手动测试评估单条工具调用的安全合规性。"""
    # Build tool_input
    if cmd is not None:
        tool_input = {"command": cmd}
    elif input_json is not None:
        try:
            tool_input = json.loads(input_json)
        except Exception as e:
            err_console.print(f"[red]无效的 JSON 参数: {e}[/red]")
            raise typer.Exit(1)
    else:
        err_console.print("[red]请提供 --cmd 或 --input 参数[/red]")
        raise typer.Exit(1)

    client = GuardClient(api_key=api_key)
    eval_result = client.evaluate_tool_call(
        tool_name=tool,
        tool_input=tool_input,
        mock=mock,
    )

    render_evaluation_result(tool_name=tool, tool_input=tool_input, eval_result=eval_result)


@app.command(name="setup")
def setup_cmd():
    """打印如何将 agent-guard 配置到 Claude Code settings.json 的说明。"""
    import shutil

    has_global_binary = shutil.which("agent-guard") is not None
    curr_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

    # Preferred command for installed package
    global_snippet = {
        "hooks": {
            "PreToolUse": [
                {
                    "matcher": "Bash|Write|Edit|NotebookEdit|mcp__.*",
                    "hooks": [{"type": "command", "command": "agent-guard hook"}],
                }
            ]
        }
    }

    # Dev/local command
    local_snippet = {
        "hooks": {
            "PreToolUse": [
                {
                    "matcher": "Bash|Write|Edit|NotebookEdit|mcp__.*",
                    "hooks": [
                        {
                            "type": "command",
                            "command": f"uv run --project {curr_dir} agent-guard hook",
                        }
                    ],
                }
            ]
        }
    }

    console.print()
    console.print("[bold green]=== Claude Code PreToolUse Hook 配置指南 ===[/bold green]")
    console.print("在你的项目根目录 [cyan].claude/settings.json[/cyan] 或全局 [cyan]~/.claude/settings.json[/cyan] 中添加以下配置：")
    console.print()

    console.print("[bold yellow]方式一：标准全局模式（推荐，通过 uv tool install agent-guard 安装）[/bold yellow]")
    console.print_json(json.dumps(global_snippet, indent=2))
    console.print()

    console.print("[bold cyan]方式二：本地源码开发模式（直接指向当前源码目录）[/bold cyan]")
    console.print_json(json.dumps(local_snippet, indent=2))
    console.print()

    console.print("[dim]提示：[/dim]")
    console.print("[dim]  1. 配置 API Key（推荐写入配置文件，一劳永逸）：[/dim]")
    console.print("[cyan]     echo 'TYPESAFE_API_KEY=\"your_key_here\"' > ~/.agentguardrc[/cyan]")
    console.print("[dim]     （亦支持环境变量 export TYPESAFE_API_KEY=\"your_key\"）[/dim]")
    console.print("[dim]  2. 可配置 AGENT_GUARD_LOG 自定义审查轨迹日志路径 (默认 ~/.claude/agent-guard.log)[/dim]")
    console.print("[dim]  3. 建议将 Claude Code 保持在 Manual 模式 (状态栏 ⏸ manual mode on，配置值 default)：[/dim]")
    console.print("[dim]     ask 档弹出带原因的原生确认框；deny 在任何权限模式 (含 bypassPermissions) 下都强制拦截[/dim]")
    console.print()


def main():
    app()


if __name__ == "__main__":
    main()
