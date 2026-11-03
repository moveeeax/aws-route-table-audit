"""Output formats: an aligned text table, JSON for pipelines, Markdown for a PR comment."""

from __future__ import annotations

import json

_HEADERS = ("SEVERITY", "ROUTE TABLE", "VPC", "FINDING")


def _rows(report: dict) -> list[tuple[str, str, str, str]]:
    rows = []
    for table in report["tables"]:
        label = table["route_table_id"]
        if table["name"]:
            label = f"{label} ({table['name']})"
        if table["main"]:
            label = f"{label} [main]"
        if not table["findings"]:
            rows.append(("ok", label, table["vpc_id"], "clean"))
            continue
        for finding in table["findings"]:
            rows.append((finding["severity"], label, table["vpc_id"], finding["message"]))
    return rows


def _wrap(text: str, width: int) -> list[str]:
    words, lines, current = text.split(), [], ""
    for word in words:
        candidate = f"{current} {word}".strip()
        if len(candidate) > width and current:
            lines.append(current)
            current = word
        else:
            current = candidate
    lines.append(current)
    return lines or [""]


def render_text(report: dict, width: int = 100) -> str:
    """An aligned table, one line per finding, long messages wrapped under the column."""
    rows = _rows(report)
    region = report.get("region") or "-"
    summary = report["summary"]
    head = f"aws-route-table-audit  region={region}  tables={summary['tables']}"
    if not rows:
        return f"{head}\n\nno route tables in scope.\n"

    widths = [max(len(_HEADERS[i]), *(len(r[i]) for r in rows)) for i in range(3)]
    finding_width = max(width - sum(widths) - 6, 32)
    lines = [head, ""]
    lines.append(
        "  ".join(
            [
                _HEADERS[0].ljust(widths[0]),
                _HEADERS[1].ljust(widths[1]),
                _HEADERS[2].ljust(widths[2]),
                _HEADERS[3],
            ]
        )
    )
    lines.append("-" * (sum(widths) + 6 + min(finding_width, 40)))
    for severity, label, vpc, message in rows:
        chunks = _wrap(message, finding_width)
        lines.append(
            "  ".join(
                [severity.ljust(widths[0]), label.ljust(widths[1]), vpc.ljust(widths[2]), chunks[0]]
            )
        )
        pad = " " * (sum(widths) + 6)
        lines.extend(f"{pad}{chunk}" for chunk in chunks[1:])
    counts = summary["findings_by_severity"]
    lines.append("")
    lines.append(
        f"{summary['findings']} findings: {counts['critical']} critical, {counts['warn']} warn. "
        f"worst: {summary['severity']}."
    )
    return "\n".join(lines) + "\n"


def render_json(report: dict) -> str:
    return json.dumps(report, indent=2, sort_keys=False, default=str) + "\n"


def render_markdown(report: dict) -> str:
    """A PR-comment table. Findings only — clean tables are counted, not listed."""
    region = report.get("region") or "-"
    summary = report["summary"]
    lines = [f"### aws-route-table-audit: `{region}`", ""]
    findings = [
        (t, f) for t in report["tables"] for f in t["findings"]
    ]
    if not findings:
        lines.append(f"No findings across {summary['tables']} route tables.")
        return "\n".join(lines) + "\n"

    lines.append("| Severity | Route table | Rule | Finding |")
    lines.append("| --- | --- | --- | --- |")
    for table, finding in findings:
        label = f"`{table['route_table_id']}`"
        if table["name"]:
            label = f"{label} {table['name']}"
        message = finding["message"].replace("|", "\\|")
        lines.append(f"| {finding['severity']} | {label} | `{finding['rule']}` | {message} |")
    counts = summary["findings_by_severity"]
    lines.append("")
    lines.append(
        f"{summary['findings']} findings across {summary['tables']} route tables: "
        f"{counts['critical']} critical, {counts['warn']} warn."
    )
    return "\n".join(lines) + "\n"


RENDERERS = {"text": render_text, "json": render_json, "markdown": render_markdown}


def render(report: dict, output_format: str) -> str:
    return RENDERERS[output_format](report)
