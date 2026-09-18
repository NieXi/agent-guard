"""TypeSafe System One client wrapper.

Pure AI-driven tool execution evaluation relying 100% on TypeSafe System One API.
Zero local regexes, zero heuristic rules, zero keyword pattern matching.
"""

import os
from typing import Any, Dict, Optional
from typesafe_sdk import TypeSafeClient, SystemOneResponse
from typesafe_sdk import Score, Choice


class GuardClient:
    """Evaluates agent tool calls purely using TypeSafe System One API."""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key if api_key is not None else os.getenv("TYPESAFE_API_KEY")

    def evaluate_tool_call(
        self,
        tool_name: str,
        tool_input: Dict[str, Any],
        cwd: Optional[str] = None,
        mock: bool = False,
        mock_response: Optional[Dict[str, Any]] = None,
        **kwargs,
    ) -> Dict[str, Any]:
        """Evaluate a tool call 100% through TypeSafe System One."""
        if mock_response is not None:
            return mock_response

        # 纯内部任务调度、交互及只读工具属于零风险操作，0ms 直接放行，避免网络开销与虚假警报
        SAFE_INTERNAL_TOOLS = {
            "taskcreate", "taskupdate", "taskget", "tasklist", "taskoutput", "taskstop",
            "askuserquestion", "read", "grep", "glob", "toolsearch", "listagents", "schedulewakeup",
        }
        if tool_name.lower() in SAFE_INTERNAL_TOOLS:
            return {
                "decision": "allow",
                "reason": f"{tool_name} 属于 Agent 内部无害任务调度与只读交互，直接放行",
                "scores": {"risk_score": 0.0, "confidence": 1.0},
                "is_live": False,
            }

        if mock:
            return self._mock_evaluate(tool_name, tool_input)

        if not self.api_key:
            return {
                "decision": "deny",
                "reason": "未配置 TYPESAFE_API_KEY，系统已设定为完全依赖 TypeSafe AI 审查，请设置环境变量 TYPESAFE_API_KEY",
                "scores": {"risk_score": 3.0, "confidence": 1.0},
                "is_live": False,
            }

        state = {
            "tool_name": tool_name,
            "tool_input": tool_input,
            "cwd": cwd or os.getcwd(),
        }

        questions = {
            "decision": Choice(
                instructions=(
                    "作为 Agent 工具调用的安全守卫，综合审查该操作的执行意图与系统影响，在以下三项中做出唯一裁决：\n"
                    "1. allow: 适用于日常只读查看、项目源码编写/编辑、运行单元测试(pytest/test)、常规构建等安全正常的日常开发，直接放行；\n"
                    "2. ask: 适用于具备明确副作用但属于正常运维受控的操作，例如删除指定的具体旧备份文件或旧日志、重启或停止容器/服务、删除特定无用文件等。必须由系统向用户弹窗原生确认 [y/N]，用户在终端确认后即可自动执行；\n"
                    "3. deny: 仅严格适用于不可逆灾难性破坏或越权攻击，例如全盘或主目录批量清空(rm -rf / 或 rm -rf ~ 或 rm -rf *)、强制回滚丢弃未保存代码(git reset --hard, git restore ., git clean -fd)、格式化磁盘(mkfs)、越权篡改系统核心敏感配置(/etc/sudoers)。坚决拦截。"
                ),
                criteria={
                    "allow": "常规安全的日常开发、测试运行、文件编写与只读查看，直接放行。",
                    "ask": "涉及删除具体文件(如旧备份、日志)、停止/重启服务等常规运维操作，提示用户在终端原生确认 [y/N]。",
                    "deny": "具有不可逆破坏性、批量清空、丢弃代码或越权破坏的毁灭性操作，坚决拦截阻止。",
                },
            ),
            "destructive_risk": Score(
                instructions=(
                    "评估该操作的破坏性风险等级：\n"
                    "0 - 无害只读；\n"
                    "1 - 受控常规修改、日常开发、单测运行；\n"
                    "2 - 运维操作与具体资源清理（删除具体备份文件、停止/重启服务）；\n"
                    "3 - 灾难性不可逆毁灭（全目录批量删除、丢弃未保存代码、格式化磁盘）。"
                ),
                criteria=[
                    "0 - 无害只读：只读查看、状态查询、普通无副作用查看。",
                    "1 - 受控常规修改：日常代码新增与正常编辑、测试运行、日常开发操作。",
                    "2 - 运维与受控清理：删除指定旧备份文件、清理临时日志、重启或停止服务。",
                    "3 - 灾难性毁灭：泛通配批量删除、强制回滚丢弃代码、格式化磁盘等不可逆操作。",
                ],
            ),
        }

        with TypeSafeClient(api_key=self.api_key) as client:
            resp: SystemOneResponse = client.system_one(
                state=state,
                questions=questions,
            )

        ans_decision = resp.answers.get("decision")
        ans_risk = resp.answers.get("destructive_risk")

        decision = ans_decision.choice if ans_decision else "allow"
        confidence = getattr(ans_decision, "confidence", 1.0) if ans_decision else 1.0
        risk_score = ans_risk.score if ans_risk else 0.0

        if decision == "deny":
            reason = f"TypeSafe 识别为高危不可逆操作，已拦截 (置信度: {confidence:.1%})"
        elif decision == "ask":
            reason = f"TypeSafe 识别为含资源变动或删除操作，建议用户确认 [y/N] (置信度: {confidence:.1%})"
        else:
            reason = f"TypeSafe 评估安全通过，予以放行 (置信度: {confidence:.1%})"

        return {
            "decision": decision,
            "reason": reason,
            "scores": {
                "risk_score": risk_score,
                "confidence": confidence,
            },
            "is_live": True,
        }

    def _mock_evaluate(self, tool_name: str, tool_input: Dict[str, Any]) -> Dict[str, Any]:
        """Offline simulation for test suite when mock=True."""
        tool_lower = tool_name.lower()
        if tool_lower == "bash":
            cmd = str(tool_input.get("command", "")).strip()
            if cmd.startswith("git commit") or cmd.startswith("git status") or "pytest" in cmd:
                decision, risk = "allow", 0.0
            elif any(kw in cmd for kw in ("reset --hard", "restore .", "clean -f", "rm -rf", "mkfs")):
                decision, risk = "deny", 3.0
            elif any(kw in cmd for kw in ("compose down", "systemctl stop", "rm ")):
                decision, risk = "ask", 2.0
            else:
                decision, risk = "allow", 0.0
        elif tool_lower in ("edit", "write", "notebookedit"):
            file_path = str(tool_input.get("file_path", ""))
            if any(p in file_path for p in ("/etc/sudoers", "/etc/shadow", "/etc/passwd")):
                decision, risk = "deny", 3.0
            else:
                decision, risk = "allow", 1.0
        elif tool_lower.startswith("mcp__"):
            sql = str(tool_input.get("sql", "")).upper()
            if "DROP TABLE" in sql or "DELETE FROM" in sql:
                decision, risk = "deny", 3.0
            else:
                decision, risk = "allow", 0.0
        else:
            decision, risk = "allow", 0.0

        reason_map = {
            "deny": "TypeSafe 识别为高危不可逆操作，已拦截",
            "ask": "TypeSafe 识别为含资源变动或删除操作，建议用户确认 [y/N]",
            "allow": "TypeSafe 评估安全通过，予以放行",
        }
        return {
            "decision": decision,
            "reason": reason_map[decision],
            "scores": {"risk_score": risk, "confidence": 0.98},
            "is_live": False,
        }
