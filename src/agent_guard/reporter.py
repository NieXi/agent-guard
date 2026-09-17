"""Rich terminal formatting and reporting for Agent Guard."""

import json
from typing import Any, Dict, Optional
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

console = Console()
err_console = Console(stderr=True)


def render_evaluation_result(
    tool_name: str,
    tool_input: Dict[str, Any],
    eval_result: Dict[str, Any],
    title: str = "TypeSafe Agent Tool Guard 评估报告",
):
    """Render a beautiful terminal report for a tool evaluation."""
    decision = eval_result.get("decision", "allow")
    reason = eval_result.get("reason", "")
    scores = eval_result.get("scores", {})
    is_live = eval_result.get("is_live", False)
    fallback_notice = eval_result.get("fallback_notice")

    # Determine status style
    if decision == "allow":
        badge = "[bold white on green]  ALLOW 允许执行  [/]"
        border_style = "green"
    elif decision == "ask":
        badge = "[bold black on yellow]  ASK 需人工确认  [/]"
        border_style = "yellow"
    else:
        badge = "[bold white on red]  DENY 拦截阻止  [/]"
        border_style = "red"

    # Input details table
    input_str = json.dumps(tool_input, ensure_ascii=False, indent=2)

    content_table = Table(show_header=False, box=None, padding=(0, 1))
    content_table.add_column("Key", style="bold cyan", width=12)
    content_table.add_column("Value")

    content_table.add_row("目标工具", f"[bold magenta]{tool_name}[/]")
    content_table.add_row("调用参数", f"[dim]{input_str}[/dim]")
    content_table.add_row("判定决策", badge)
    content_table.add_row("判定原因", f"[bold]{reason}[/bold]")

    # Dimension Scores table
    score_table = Table(title="多维度评定指标", show_header=True, header_style="bold blue")
    score_table.add_column("维度", style="bold")
    score_table.add_column("指标值", justify="center")
    score_table.add_column("说明", style="dim")

    risk_score = scores.get("risk_score", 0)
    violation_prob = scores.get("violation_prob", 0.0)
    confidence = scores.get("confidence", 1.0)

    # Risk level styling
    risk_colors = ["green", "cyan", "yellow", "red"]
    idx = max(0, min(int(round(risk_score)), 3))
    risk_color = risk_colors[idx]
    risk_labels = ["0 - 无害只读", "1 - 受控修改", "2 - 中度风险/关键变动", "3 - 高危不可逆/严重破坏"]

    score_table.add_row(
        "破坏性风险 (Score)",
        f"[{risk_color}]{risk_score:.2f} / 3[/{risk_color}]",
        risk_labels[idx],
    )
    score_table.add_row(
        "违规概率 (Noul)",
        f"{violation_prob:.1%}",
        "违反安全原则或不可逆操作的概率",
    )
    score_table.add_row(
        "置信度 (Confidence)",
        f"{confidence:.1%}",
        "模型判定分布确定性",
    )

    # Engine source
    source_tag = "[bold green]TypeSafe Jev (System One)[/]" if is_live else "[bold yellow]本地安全启发规则 (Fallback)[/]"
    footer_text = f"评判引擎: {source_tag}"
    if fallback_notice:
        footer_text += f" | [dim]{fallback_notice}[/dim]"

    console.print()
    console.print(
        Panel(
            content_table,
            title=f"[bold]{title}[/bold]",
            subtitle=footer_text,
            border_style=border_style,
            padding=(1, 2),
        )
    )
    console.print(score_table)
    console.print()
