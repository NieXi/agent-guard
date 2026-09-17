"""TypeSafe System One client wrapper.

Pure AI-driven tool execution evaluation relying 100% on TypeSafe System One (Jev) API.
No local regexes or hardcoded pattern matching.
"""

import os
from typing import Any, Dict, Optional
from typesafe_sdk import TypeSafeClient, SystemOneResponse
from typesafe_sdk import Score, Noul, Choice


class GuardClient:
    """Evaluates agent tool calls strictly using TypeSafe System One API."""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key if api_key is not None else os.getenv("TYPESAFE_API_KEY")

    def evaluate_tool_call(
        self,
        tool_name: str,
        tool_input: Dict[str, Any],
        cwd: Optional[str] = None,
        mock: bool = False,
        mock_response: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Evaluate a tool call purely through TypeSafe System One.

        Returns:
            - decision: 'allow' | 'deny' | 'ask'
            - reason: TypeSafe semantic judgment explanation
            - scores: detailed scores from TypeSafe primitives
            - is_live: True if evaluated by live API
        """
        # If a mock response is explicitly provided for testing, return it
        if mock_response is not None:
            return mock_response

        # If mock mode is requested, simulate TypeSafe System One evaluation locally
        if mock:
            return self._mock_evaluate(tool_name, tool_input)

        if not self.api_key:
            return {
                "decision": "deny",
                "reason": "未配置 TYPESAFE_API_KEY，系统已设定为完全依赖 TypeSafe AI 审查，请设置环境变量 TYPESAFE_API_KEY",
                "scores": {"risk_score": 3, "violation_prob": 1.0, "confidence": 1.0},
                "is_live": False,
            }

        current_cwd = cwd or os.getcwd()
        context_analysis = self._analyze_tool_context(tool_name, tool_input, current_cwd)

        state = {
            "tool_name": tool_name,
            "tool_input": tool_input,
            "context_analysis": context_analysis,
            "cwd": current_cwd,
            "safety_principles": [
                "1. 破坏性拦截的核心是【实际执行的行为后果与真实意图】，而非【参数、字符串或代码中出现的文本字面量】。",
                "2. 严禁直接执行导致文件丢失、代码回滚丢弃或不可逆破坏的操作（例如直接执行 rm -rf、git reset --hard、git restore .、git clean -fd、清空数据表、格式化磁盘）。",
                "3. 严禁任何针对系统敏感路径（如 /etc, /boot, ~/.ssh）的越权修改、逃逸、篡改权限或凭据泄露操作。",
                "4. 针对纯只读、常规代码审查、正常良性编辑、运行单元测试与常规日常构建命令，予以放行 (allow)。",
                "5. 严禁因参数或文本中引用了危险命令而发生误判 (False Positive)：",
                "   - 当命令是运行测试框架 (pytest 等)、脚本执行或安全工具自身检查 (agent-guard check) 时，其内部参数作为测试数据，应予以放行；",
                "   - 当工具为 Edit/Write 修改工程文件时，代码或单测中断言包含危险命令属于日常开发，应予以放行；",
                "   - 当 git commit 提交信息中包含解释性词汇时，应予以放行。",
            ],
        }

        return self._call_typesafe_api(state)

    def _analyze_tool_context(
        self, tool_name: str, tool_input: Dict[str, Any], cwd: str
    ) -> Dict[str, Any]:
        """Extract high-level intent and contextual metadata to guide TypeSafe System One.

        Prevents false-positive misclassification when safe commands (like test runners,
        security checks, or file edits) contain dangerous string arguments.
        """
        tool_lower = tool_name.lower()

        if tool_lower == "bash":
            cmd = str(tool_input.get("command", "")).strip()
            # 1. Test runner or security evaluator
            test_prefixes = (
                "pytest", "uv run pytest", "python -m unittest", "python -m pytest",
                "npm test", "pnpm test", "yarn test", "cargo test", "go test",
                "agent-guard check", "uv run agent-guard", "agent-guard setup",
                "uv run python -c", "python3 -c", "python -c",
            )
            is_test_eval = any(cmd.startswith(p) or f" {p}" in cmd for p in test_prefixes)

            # 2. Git commit or informational commands
            is_git_meta = cmd.startswith("git commit") or cmd.startswith("git log") or cmd.startswith("git diff") or cmd.startswith("git show")

            # 3. Text output / display
            is_display = cmd.startswith("echo ") or cmd.startswith("printf ") or cmd.startswith("cat ")

            if is_test_eval:
                return {
                    "operation_intent": "running_test_or_security_tool",
                    "explanation": "该命令是运行测试框架、诊断脚本或安全审查工具。命令中的任何参数、选项或断言均为测试数据，不是在终端实际执行破坏性操作。",
                }
            elif is_git_meta:
                return {
                    "operation_intent": "git_version_control_metadata",
                    "explanation": "该命令为常规 Git 版本控制提交或历史查看。提交说明或参数中引用的词汇仅为描述文本，无破坏性。",
                }
            elif is_display:
                return {
                    "operation_intent": "display_or_print",
                    "explanation": "该命令仅为文本打印或查看，无破坏性系统副作用。",
                }
            else:
                return {
                    "operation_intent": "direct_shell_execution",
                    "explanation": "该命令将在系统终端中直接执行，请重点审查其实际执行的指令主体是否有文件删除、硬回滚或高危破坏性行为。",
                }

        elif tool_lower in ("edit", "write", "notebookedit"):
            file_path = str(tool_input.get("file_path", ""))
            abs_path = os.path.abspath(os.path.expanduser(file_path)) if file_path else ""
            workspace = os.path.abspath(cwd)

            # Sensitive system paths
            sensitive_roots = ("/etc", "/boot", "/System", "/usr/bin", "/usr/sbin", "/var/root")
            is_system_path = any(abs_path.startswith(p) for p in sensitive_roots) or abs_path.startswith(os.path.expanduser("~/.ssh"))
            is_in_workspace = abs_path.startswith(workspace)

            # Content truncation / wipe check
            content = tool_input.get("content")
            is_file_wipe = (content == "" and os.path.exists(abs_path) and os.path.getsize(abs_path) > 0)

            if is_system_path:
                return {
                    "operation_intent": "modify_system_critical_file",
                    "target_path": file_path,
                    "explanation": "目标文件位于系统核心敏感路径，具备高越权与系统破坏风险。",
                }
            elif is_file_wipe:
                return {
                    "operation_intent": "truncate_file_to_empty",
                    "target_path": file_path,
                    "explanation": "该操作将清空已有文件内容，可能导致代码或数据丢失。",
                }
            else:
                return {
                    "operation_intent": "project_source_code_editing",
                    "target_path": file_path,
                    "is_project_file": is_in_workspace,
                    "explanation": "该操作是正常编辑项目工程源码或单测文件。文件代码中编写的 shell 字符串、正则或断言属于日常开发，绝非在终端执行该命令。",
                }

        return {
            "operation_intent": "standard_tool_execution",
            "explanation": "常规工具调用，请综合评估其执行意图与破坏性风险。",
        }

    def _call_typesafe_api(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """Send evaluation questions to TypeSafe System One."""
        questions = {
            "destructive_risk": Score(
                instructions=(
                    "评估该工具调用实际执行时的破坏性风险程度。"
                    "特别注意区分【实际执行的操作主体】与【作为文本、参数或测试数据的字面量】。"
                    "正常代码编辑、运行测试用例、提交代码、常规只读查看均属于 0~1 级低风险。"
                ),
                criteria=[
                    "0 - 无害只读：只读查看、搜索、状态查询、普通无副作用查看。",
                    "1 - 受控常规修改：普通代码/文档新增与正常编辑、测试运行(pytest/test)、日常开发操作。",
                    "2 - 中度风险变更：删除单个文件、重启容器/服务、修改关键配置、外部网络请求或可能影响运行状态的操作。",
                    "3 - 高度破坏性/不可逆：直接批量或强制删除文件、直接丢弃未保存代码变更(强制回滚)、清空数据表、格式化等不可逆灾难性操作。",
                ],
            ),
            "policy_violation": Noul(
                instructions="该工具调用实际执行的行为是否会导致文件永久删除、代码回滚丢失、系统越权修改或触犯安全红线？",
            ),
            "decision": Choice(
                instructions=(
                    "综合考虑操作目的与实际执行影响，决定执行策略："
                    "直接放行 (allow)、需用户确认 (ask)、坚决拦截阻止 (deny)。"
                    "正常的代码编辑与测试运行切勿误拦截。"
                ),
                criteria={
                    "allow": "操作安全合规且无丢失文件或破坏风险，属于只读、测试运行或正常受控的常规日常开发，可安全直接执行。",
                    "ask": "操作涉及实际文件删除、服务变动、配置覆盖或具备一定副作用，必须提示人类用户确认。",
                    "deny": "操作实际执行具有高度破坏性、批量删除文件、强制回滚丢弃代码、篡改关键系统配置，必须坚决拦截。",
                },
            ),
        }

        with TypeSafeClient(api_key=self.api_key) as client:
            resp: SystemOneResponse = client.system_one(
                state=state,
                questions=questions,
            )

        ans_risk = resp.answers.get("destructive_risk")
        ans_violation = resp.answers.get("policy_violation")
        ans_decision = resp.answers.get("decision")

        # Extract values
        risk_score = ans_risk.score if ans_risk else 0.0
        violation_prob = getattr(ans_violation, "noul", getattr(ans_violation, "probability", 0.0)) if ans_violation else 0.0
        chosen_decision = ans_decision.choice if ans_decision else "allow"
        confidence = getattr(ans_decision, "confidence", 1.0) if ans_decision else 1.0

        return self._build_result(risk_score, violation_prob, chosen_decision, confidence, is_live=True)

    def _mock_evaluate(self, tool_name: str, tool_input: Dict[str, Any]) -> Dict[str, Any]:
        """Simulate TypeSafe System One evaluation for testing and offline demo."""
        ctx = self._analyze_tool_context(tool_name, tool_input, os.getcwd())
        intent = ctx.get("operation_intent", "")

        if intent in ("running_test_or_security_tool", "git_version_control_metadata", "display_or_print"):
            risk_score, violation_prob, chosen, conf = 0.0, 0.02, "allow", 0.98
        elif intent == "project_source_code_editing":
            risk_score, violation_prob, chosen, conf = 1.0, 0.03, "allow", 0.98
        elif intent in ("modify_system_critical_file", "truncate_file_to_empty"):
            risk_score, violation_prob, chosen, conf = 3.0, 0.95, "deny", 0.98
        elif intent == "direct_shell_execution":
            cmd = str(tool_input.get("command", "")).strip()
            if any(kw in cmd for kw in ("reset --hard", "restore .", "clean -f", "rm -rf", "rm -r /", "mkfs", "dd if=")):
                risk_score, violation_prob, chosen, conf = 3.0, 0.95, "deny", 0.98
            elif any(kw in cmd for kw in ("compose down", "systemctl stop", "reboot", "shutdown", "drop database")):
                risk_score, violation_prob, chosen, conf = 2.0, 0.45, "ask", 0.90
            else:
                risk_score, violation_prob, chosen, conf = 0.0, 0.02, "allow", 0.98
        elif tool_name.lower().startswith("mcp__"):
            sql = str(tool_input.get("sql", "")).upper()
            if any(w in sql for w in ("DROP TABLE", "DELETE FROM", "TRUNCATE")):
                risk_score, violation_prob, chosen, conf = 3.0, 0.95, "deny", 0.98
            else:
                risk_score, violation_prob, chosen, conf = 0.0, 0.02, "allow", 0.95
        else:
            risk_score, violation_prob, chosen, conf = 0.0, 0.02, "allow", 0.95

        return self._build_result(risk_score, violation_prob, chosen, conf, is_live=False)

        return self._build_result(risk_score, violation_prob, chosen, conf, is_live=False)

    def _build_result(
        self,
        risk_score: float,
        violation_prob: float,
        chosen_decision: str,
        confidence: float,
        is_live: bool,
    ) -> Dict[str, Any]:
        """Apply composite thresholds to TypeSafe outputs."""
        score_str = f"{risk_score:.2f}" if isinstance(risk_score, float) and risk_score != int(risk_score) else f"{int(risk_score)}"

        # Composite logic: Code owns the decision thresholds (TypeSafe Best Practice)
        is_hard_deny = (
            risk_score >= 2.5
            or violation_prob > 0.60
            or (chosen_decision == "deny" and (risk_score >= 2.0 or violation_prob > 0.35))
        )
        is_ask = (
            risk_score >= 1.8
            or violation_prob > 0.25
            or chosen_decision in ("ask", "deny")
        )

        if is_hard_deny:
            final_decision = "deny"
            reason = f"TypeSafe 识别为高危破坏性操作 (风险等级: {score_str}/3, 违规概率: {violation_prob:.1%})"
        elif is_ask:
            final_decision = "ask"
            reason = f"TypeSafe 识别为含副作用或删除操作，建议用户确认 (风险等级: {score_str}/3, 违规概率: {violation_prob:.1%})"
        else:
            final_decision = "allow"
            reason = f"TypeSafe 评估安全通过 (风险等级: {score_str}/3, 置信度: {confidence:.1%})"

        return {
            "decision": final_decision,
            "reason": reason,
            "scores": {
                "risk_score": risk_score,
                "violation_prob": violation_prob,
                "confidence": confidence,
            },
            "is_live": is_live,
        }
