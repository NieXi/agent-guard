# cmd-guard · TypeSafe Agent Tool Guard

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
uv tool install cmd-guard

# 或使用 pipx
pipx install cmd-guard
```

> PyPI 项目页：<https://pypi.org/project/cmd-guard/> · GitHub 仓库：<https://github.com/NieXi/agent-guard>
>
> 安装后的命令名为 `agent-guard`（PyPI 发行名与命令名不同）。

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
        "matcher": "Bash|Write|Edit|NotebookEdit|mcp__.*",
        "hooks": [
          {
            "type": "command",
            "command": "agent-guard hook"
          }
        ]
      }
    ]
  }
}
```

- **`matcher`**：指定需要拦截审核的工具（推荐拦截 `Bash|Write|Edit|NotebookEdit|mcp__.*`，覆盖终端命令、文件写入以及全量 MCP 工具）。
- **`hooks[].command`**：Claude Code 在执行这些工具前，会自动将调用参数经 `stdin` 喂给 `agent-guard hook`。

### 3. 权限模式：建议使用 Manual 模式

建议将 Claude Code 保持在 **Manual 模式**（状态栏显示 `⏸ manual mode on`；配置值为 `default`，CLI 标签与 `manual` 别名自 Claude Code v2.1.200 起，可用 `claude --permission-mode manual` 或 `"defaultMode": "manual"` 设置）。该模式下 Claude Code 在大多数编辑、Shell、网络操作前都会征询确认，本 hook 的 `ask` 决策会弹出带原因的原生确认框，且该确认框不会附带"切换到 auto 模式"的快捷选项。

其他权限模式下 hook 依然全程生效，安全语义不变：

- **`deny`**：在包括 `bypassPermissions` / `--dangerously-skip-permissions` 在内的任何模式下都强制拦截，无法通过切换权限模式绕过；
- **`ask`**：在无提示面的场景（`dontAsk`、无人值守 headless `-p` 会话）不会被静默放行，而是自动转为**拒绝**（fail-closed）。

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

支持以下两种配置方式（推荐配置文件方式，免除子进程环境变量丢失困扰）：

**方式一：写入全局配置文件 `~/.agentguardrc`（推荐）**
```bash
echo 'TYPESAFE_API_KEY="your_api_key_here"' > ~/.agentguardrc
```
（亦支持在项目根目录下创建 `./.agentguardrc` 实现项目级隔离配置）

**方式二：配置系统环境变量**
```bash
export TYPESAFE_API_KEY="your_api_key_here"
```

---

## 自动化测试

项目已配备完善的测试套件：
```bash
uv run pytest
```
