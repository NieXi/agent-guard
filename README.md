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
- ⚡ **Fail-Safe 安全保护**：在未配置 Key 或遭遇格式异常时自动执行安全兜底，坚决防止未知命令静默绕过。支持离线 `--mock` 快速测试与演示。
- 📊 **Rich 彩色终端报告**：提供直观的命令调试面板，展示各维度指标、概率分布与决策依据。
- 📝 **审计日志支持**：配置 `AGENT_GUARD_LOG` 环境变量可持久化所有工具调用的审核轨迹（JSONL 格式）。

---

## 安装方式

推荐使用 `uv tool` 全局安装（环境隔离且自动注入 PATH）：

```bash
# 推荐方式
uv tool install agent-guard

# 或使用 pipx
pipx install agent-guard
```

---

## 快速接入 Claude Code

### 1. 查看配置建议

```bash
agent-guard setup
# 或源码开发时使用
uv run agent-guard setup
```

### 2. 添加到 Claude Code 配置

在你的全局配置 `~/.claude/settings.json`（对所有项目生效）或项目根目录 `.claude/settings.json` 中添加：

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
agent-guard check --cmd "git status"

# 测试高危破坏性命令 -> 输出 DENY 并说明原因
agent-guard check --cmd "git reset --hard HEAD~1"

# 测试涉及服务的变动 -> 输出 ASK 建议人工确认
agent-guard check --cmd "docker compose down"

# 测试敏感系统文件篡改 -> 输出 DENY 拦截
agent-guard check --tool Write --input '{"file_path": "/etc/sudoers", "content": "test"}'

# 离线模拟测试（无需 API Key）
agent-guard check --mock --cmd "git reset --hard HEAD~1"
```

### 2. 模拟 Hook 管道输入 (stdin)

```bash
echo '{"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "git diff"}}' | agent-guard hook
```

输出：
```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "allow",
    "permissionDecisionReason": "[TypeSafe Guard] TypeSafe 评估安全通过 (风险等级: 0/3, 置信度: 98.0%)"
  }
}
```

### 3. 配置 TypeSafe API Key

在系统环境或者 `~/.zshrc` / `.bashrc` 中配置：
```bash
export TYPESAFE_API_KEY="your_api_key_here"
```

---

## 自动化测试

项目已配备完善的测试套件：
```bash
uv run pytest
```
