# TypeSafe Agent Tool Guard (agent-guard)

基于 **TypeSafe AI (System One / Jev)** 的 Agent 工具调用安全合规守卫与评估器，专为 **Claude Code `PreToolUse` Hook** 深度定制。

在 Agent（Claude Code 等）执行工具调用（如 `Bash` 命令、`Write`、`Edit` 文件编辑）前进行毫秒级实时审查，多维度判定其**破坏性风险**与**规则合规性**，精准拦截破坏性删除、强制回滚与越权敏感操作。

---

## 核心特性

- 🛡️ **Claude Code 原生 Hook 对齐**：完全支持官方 `PreToolUse` 交互协议，返回标准 `hookSpecificOutput`（`allow` / `deny` / `ask`）。
- 🧠 **TypeSafe System One 驱动**：
  - **破坏性风险 (`destructive_risk` - Score)**：四级阶梯场景判定（只读 ➔ 受控常规修改 ➔ 服务重启/中度风险 ➔ 破坏性/不可逆高危）。
  - **安全守则合规 (`policy_violation` - Noul)**：二元概率判断是否触犯安全红线。
  - **执行裁决 (`decision` - Choice)**：`allow`（直接放行）、`ask`（需人工确认）、`deny`（拦截阻止）。
- ⚡ **智能安全兜底 (Heuristic Fallback)**：即使无网络或未配置 `TYPESAFE_API_KEY`，内置的高精度安全规则引擎也会守卫核心红线（拦截 `rm -rf`、`git reset --hard`、`git restore .`、系统敏感文件篡改等）。
- 📊 **Rich 彩色终端报告**：提供直观的命令调试面板，展示各维度指标、概率分布与决策依据。
- 📝 **审计日志支持**：配置 `AGENT_GUARD_LOG` 环境变量可持久化所有工具调用的审核轨迹（JSONL 格式）。

---

## 快速接入 Claude Code

### 1. 查看配置建议

在项目目录下执行：
```bash
uv run agent-guard setup
```

### 2. 添加到 Claude Code 配置

在项目根目录 `.claude/settings.json`（仅对本项目生效）或 `~/.claude/settings.json`（全局生效）中添加：

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|Write|Edit",
        "command": "agent-guard hook"
      }
    ]
  }
}
```

- **`matcher`**：指定需要拦截审核的工具（推荐拦截 `Bash|Write|Edit`）。
- **`command`**：Claude Code 在执行这些工具前，会自动将调用参数经 `stdin` 喂给 `agent-guard hook`。

---

## CLI 命令使用

### 1. 手动测试评估一条命令

```bash
# 测试只读安全命令 -> 输出 ALLOW
uv run agent-guard check --cmd "git status"

# 测试高危破坏性命令 -> 输出 DENY 并说明原因
uv run agent-guard check --cmd "git reset --hard HEAD~1"

# 测试涉及服务的变动 -> 输出 ASK 建议人工确认
uv run agent-guard check --cmd "docker compose down"

# 测试敏感系统文件篡改 -> 输出 DENY 拦截
uv run agent-guard check --tool Write --input '{"file_path": "/etc/sudoers", "content": "test"}'
```

### 2. 模拟 Hook 管道输入 (stdin)

```bash
echo '{"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "git diff"}}' | uv run agent-guard hook
```

输出：
```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "allow",
    "permissionDecisionReason": "[TypeSafe Guard] 常规 Bash 命令，无高危或破坏性特征"
  }
}
```

### 3. 配置 TypeSafe API Key

在环境或者 `.env` 中配置：
```bash
export TYPESAFE_API_KEY="your_api_key_here"
```
未配置时将自动启用本地规则防护引擎。

---

## 自动化测试

项目已配备完善的测试套件：
```bash
uv run pytest
```
