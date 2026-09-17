"""TypeSafe System One client wrapper with fallback and mock support."""

import os
from typing import Any, Dict, Optional
from typesafe_sdk import TypeSafeClient, SystemOneResponse
from typesafe_sdk import Score, Noul, Choice


class GuardClient:
    """Wrapper for TypeSafe System One client handling API requests and graceful fallbacks."""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("TYPESAFE_API_KEY")
        self.has_key = bool(self.api_key)

    def evaluate_tool_call(
        self,
        tool_name: str,
        tool_input: Dict[str, Any],
        cwd: Optional[str] = None,
        mock: bool = False,
    ) -> Dict[str, Any]:
        """Evaluate a tool call using TypeSafe System One or heuristic fallback.

        Returns a dictionary containing:
        - decision: 'allow' | 'deny' | 'ask'
        - reason: explanation of the decision
        - scores: details on individual dimensions
        - is_live: whether this was evaluated by live TypeSafe API
        """
        state = {
            "tool_name": tool_name,
            "tool_input": tool_input,
            "cwd": cwd or os.getcwd(),
            "core_rules": [
                "1. 任何会导致文件或修改丢失的操作（如 git reset --hard、git restore .、git clean -fd、rm -rf 等），严禁静默执行，必须拦截或由用户确认",
                "2. 严禁直接使用 git restore . 回滚所有文件",
                "3. git push 禁止直接使用 --force，必须使用 --force-with-lease",
                "4. 严禁向外部或不安全存储明文泄露 API Key、Token、私钥等核心凭据",
                "5. 严禁任意修改系统关键文件或越权逃逸",
                "6. 纯只读或受控的良性编辑操作应予以放行",
            ],
        }

        if self.has_key and not mock:
            try:
                return self._call_typesafe_api(state)
            except Exception as e:
                # If API call fails (network, rate limit, etc.), fallback to safe heuristics
                result = self._heuristic_evaluate(state)
                result["fallback_notice"] = f"TypeSafe API 调用异常 ({e})，已自动切换为安全规则守卫"
                return result

        # Mock / Local Heuristic fallback
        result = self._heuristic_evaluate(state)
        if not self.has_key:
            result["fallback_notice"] = "未检测到 TYPESAFE_API_KEY，当前由内置安全合规规则守卫"
        return result

    def _call_typesafe_api(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """Send evaluation questions to TypeSafe System One."""
        questions = {
            "destructive_risk": Score(
                instructions="评估该工具调用对系统、文件或代码库的破坏性程度与潜在损失风险。",
                criteria=[
                    "无害只读：只读查看、搜索、状态检查(如 ls, git status, rg, fd, cat)。",
                    "受控常规编辑：良性的代码或文档文件修改、测试运行、日常开发操作。",
                    "中度风险变更：重启核心服务、安装系统包、修改网络/DNS配置或对外发送请求。",
                    "高度破坏性或不可逆：导致文件彻底删除(rm -rf)、丢弃代码更改(git reset --hard, git restore .)、覆盖配置、泄露密钥凭据等高危操作。",
                ],
            ),
            "policy_violation": Noul(
                instructions="该工具调用是否违反了安全守则（包含不可逆文件删除、丢弃未保存更改、明文泄密或越权高危命令）？",
            ),
            "decision": Choice(
                instructions="综合考虑安全性与规则守则，该操作应该直接允许、提示用户确认、还是坚决拦截？",
                criteria={
                    "allow": "操作安全合规，属于只读或正常受控的常规操作，可安全执行。",
                    "ask": "操作涉及服务重启、关键配置变动或潜在副作用，建议提示用户确认。",
                    "deny": "包含严重破坏性、数据丢失风险或明确违反安全原则的高危操作，必须拦截。",
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
        risk_score = ans_risk.score if ans_risk else 0
        violation_prob = ans_violation.probability if ans_violation else 0.0
        chosen_decision = ans_decision.choice if ans_decision else "allow"

        # Code owns the final safety gate (TypeSafe best practice):
        # Even if choice is allow, if violation probability is very high or risk is max (3), enforce deny/ask.
        if risk_score == 3 or violation_prob > 0.65:
            final_decision = "deny"
            reason = f"TypeSafe 识别为高破坏性风险 (风险等级: {risk_score}/3, 违规概率: {violation_prob:.2%})"
        elif risk_score == 2 or violation_prob > 0.35:
            final_decision = "ask"
            reason = f"TypeSafe 识别为中度风险操作，建议用户确认 (风险等级: {risk_score}/3)"
        else:
            final_decision = chosen_decision
            reason = f"TypeSafe 评估通过 (风险等级: {risk_score}/3)"

        return {
            "decision": final_decision,
            "reason": reason,
            "scores": {
                "risk_score": risk_score,
                "violation_prob": violation_prob,
                "confidence": getattr(ans_decision, "confidence", 1.0) if ans_decision else 1.0,
            },
            "is_live": True,
        }

    def _heuristic_evaluate(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """Local heuristic safety guard for offline, tests, or API failure fallback."""
        tool_name = state.get("tool_name", "")
        tool_input = state.get("tool_input", {})

        # High-risk patterns that MUST be denied
        hard_deny_patterns = [
            ("git reset --hard", "严禁未经确认执行 git reset --hard 回滚操作"),
            ("git restore .", "严禁直接执行 git restore . 回滚所有修改"),
            ("git clean -f", "严禁未经逐个确认执行 git clean 清理未跟踪文件"),
            ("rm -rf", "严禁执行高危 rm -rf 批量删除操作"),
            ("rm -r /", "检测到根路径或批量删除指令"),
            ("git push -f", "禁止使用 --force 强推，请使用 --force-with-lease"),
            ("mkfs", "严禁执行格式化命令"),
            ("dd if=", "检测到底层磁盘裸写命令"),
            (":(){ :|:& };:", "检测到 Fork 炸弹攻击命令"),
        ]

        # Medium-risk patterns that should ASK user
        ask_patterns = [
            ("docker compose down", "停止/销毁容器服务"),
            ("systemctl stop", "停止系统服务"),
            ("reboot", "重启系统"),
            ("shutdown", "关机"),
            ("drop database", "删除数据库"),
            ("truncate table", "清空数据表"),
            ("curl", "对外发送网络请求"),
        ]

        # 1. Check Bash commands
        if tool_name.lower() == "bash":
            import re
            cmd = str(tool_input.get("command", "")).strip()

            # Regex-based precise command matching (handles prefixes like ; && | or beginning of line)
            hard_deny_regexes = [
                (r"(?:^|[;&|]\s*)(?:sudo\s+)?rm\s+-[^\s]*[rf]", "严禁执行高危 rm -rf / rm -r 批量删除操作"),
                (r"(?:^|[;&|]\s*)git\s+reset\s+--hard", "严禁未经确认执行 git reset --hard 回滚操作"),
                (r"(?:^|[;&|]\s*)git\s+restore\s+\.", "严禁直接执行 git restore . 回滚所有修改"),
                (r"(?:^|[;&|]\s*)git\s+clean\s+-[^\s]*f", "严禁未经逐个确认执行 git clean 清理未跟踪文件"),
                (r"(?:^|[;&|]\s*)git\s+push\s+.*(?:-f\b|--force\b)(?!-with-lease)", "禁止使用 --force 强推，请使用 --force-with-lease"),
                (r"(?:^|[;&|]\s*)mkfs\b", "严禁执行格式化命令"),
                (r"(?:^|[;&|]\s*)dd\s+if=", "检测到底层磁盘裸写命令"),
                (r":\(\)\s*\{\s*:\|:&\s*\}\s*;\s*:", "检测到 Fork 炸弹攻击命令"),
            ]

            ask_regexes = [
                (r"(?:^|[;&|]\s*)docker\s+compose\s+down\b", "停止/销毁容器服务"),
                (r"(?:^|[;&|]\s*)(?:sudo\s+)?systemctl\s+stop\b", "停止系统服务"),
                (r"(?:^|[;&|]\s*)(?:sudo\s+)?reboot\b", "重启系统"),
                (r"(?:^|[;&|]\s*)(?:sudo\s+)?shutdown\b", "关机"),
                (r"\bdrop\s+database\b", "删除数据库"),
                (r"\btruncate\s+table\b", "清空数据表"),
            ]

            for pattern, desc in hard_deny_regexes:
                if re.search(pattern, cmd, re.IGNORECASE):
                    return {
                        "decision": "deny",
                        "reason": f"触犯安全红线: {desc} (命中指令: {cmd.splitlines()[0]})",
                        "scores": {"risk_score": 3, "violation_prob": 0.99, "confidence": 1.0},
                        "is_live": False,
                    }

            for pattern, desc in ask_regexes:
                if re.search(pattern, cmd, re.IGNORECASE):
                    return {
                        "decision": "ask",
                        "reason": f"操作具备较高副作用: {desc} (命中指令: {cmd.splitlines()[0]})",
                        "scores": {"risk_score": 2, "violation_prob": 0.50, "confidence": 0.9},
                        "is_live": False,
                    }

            return {
                "decision": "allow",
                "reason": "常规 Bash 命令，无高危或破坏性特征",
                "scores": {"risk_score": 0, "violation_prob": 0.05, "confidence": 0.95},
                "is_live": False,
            }

        # 2. Check File Edit / Write tools
        elif tool_name.lower() in ("edit", "write", "notebookedit"):
            file_path = str(tool_input.get("file_path", ""))
            dangerous_paths = [
                "/etc/sudoers",
                "/etc/shadow",
                "/etc/passwd",
                "/.ssh/authorized_keys",
                "/boot",
            ]
            for dp in dangerous_paths:
                if dp in file_path:
                    return {
                        "decision": "deny",
                        "reason": f"严禁越权修改系统敏感文件: {file_path}",
                        "scores": {"risk_score": 3, "violation_prob": 0.95, "confidence": 1.0},
                        "is_live": False,
                    }

            return {
                "decision": "allow",
                "reason": "常规代码/配置文件变更",
                "scores": {"risk_score": 1, "violation_prob": 0.10, "confidence": 0.95},
                "is_live": False,
            }

        # 3. Check MCP (Model Context Protocol) tools
        elif tool_name.startswith("mcp__"):
            tool_lower = tool_name.lower()
            input_str = str(tool_input).lower()

            # High-risk MCP actions (e.g. deleting repos, dropping tables, wiping data)
            mcp_danger_actions = ["delete", "drop", "destroy", "truncate", "wipe", "format", "purge"]
            for action in mcp_danger_actions:
                if action in tool_lower or f"'{action}" in input_str or f'"{action}' in input_str:
                    return {
                        "decision": "deny",
                        "reason": f"检测到 MCP 破坏性调用 [{tool_name}]，包含高危动作 '{action}'",
                        "scores": {"risk_score": 3, "violation_prob": 0.90, "confidence": 0.95},
                        "is_live": False,
                    }

            # Medium-risk MCP actions (creating resources, publishing, modifying state)
            mcp_modify_actions = ["create", "post", "put", "update", "patch", "execute", "exec", "write"]
            for action in mcp_modify_actions:
                if action in tool_lower:
                    return {
                        "decision": "ask",
                        "reason": f"MCP 工具 [{tool_name}] 涉及外部写操作或变更，建议人工确认",
                        "scores": {"risk_score": 2, "violation_prob": 0.40, "confidence": 0.90},
                        "is_live": False,
                    }

            # Read-only or query MCP tools
            return {
                "decision": "allow",
                "reason": f"MCP 只读或常规查询工具 ({tool_name})",
                "scores": {"risk_score": 0, "violation_prob": 0.05, "confidence": 0.95},
                "is_live": False,
            }

        # Default: allow read-only or standard internal tools (Read, Glob, Grep, etc.)
        return {
            "decision": "allow",
            "reason": f"安全只读或标准工具 ({tool_name})",
            "scores": {"risk_score": 0, "violation_prob": 0.0, "confidence": 1.0},
            "is_live": False,
        }
