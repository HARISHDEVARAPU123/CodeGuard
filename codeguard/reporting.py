"""Generate console, Markdown, HTML, and JSON reports from a CodeGuard Report."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from jinja2 import Environment, select_autoescape
from rich.console import Console
from rich.table import Table
from rich.text import Text

from codeguard.models import CheckResult, Finding, Report

_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>CodeGuard Quality Gate Report</title>
  <style>
    :root {
      --bg: #f8fafc;
      --card-bg: #ffffff;
      --text: #0f172a;
      --border: #e2e8f0;
      --pass: #16a34a;
      --fail: #dc2626;
      --error: #9333ea;
      --critical: #b91c1c;
      --high: #ea580c;
      --medium: #ca8a04;
      --low: #0284c7;
    }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background-color: var(--bg);
      color: var(--text);
      line-height: 1.5;
      margin: 0;
      padding: 2rem;
    }
    .container {
      max-width: 1100px;
      margin: 0 auto;
    }
    .header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 2rem;
      padding-bottom: 1rem;
      border-bottom: 1px solid var(--border);
    }
    h1 { margin: 0; font-size: 1.75rem; font-weight: 700; }
    .badge {
      display: inline-block;
      padding: 0.35rem 0.75rem;
      border-radius: 9999px;
      font-size: 0.875rem;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }
    .badge-PASS { background-color: #dcfce7; color: var(--pass); }
    .badge-FAIL { background-color: #fee2e2; color: var(--fail); }
    .badge-ERROR { background-color: #f3e8ff; color: var(--error); }
    .badge-CRITICAL { background-color: #fee2e2; color: var(--critical); }
    .badge-HIGH { background-color: #ffedd5; color: var(--high); }
    .badge-MEDIUM { background-color: #fef9c3; color: var(--medium); }
    .badge-LOW { background-color: #e0f2fe; color: var(--low); }
    .card {
      background: var(--card-bg);
      border-radius: 8px;
      border: 1px solid var(--border);
      padding: 1.5rem;
      margin-bottom: 1.5rem;
      box-shadow: 0 1px 3px rgba(0,0,0,0.05);
    }
    h2 { font-size: 1.25rem; margin-top: 0; margin-bottom: 1rem; }
    table {
      width: 100%;
      border-collapse: collapse;
      text-align: left;
    }
    th, td {
      padding: 0.75rem 1rem;
      border-bottom: 1px solid var(--border);
      font-size: 0.875rem;
    }
    th {
      background-color: #f1f5f9;
      font-weight: 600;
      color: #475569;
    }
    tr:last-child td { border-bottom: none; }
    .stats {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 1rem;
      margin-bottom: 1.5rem;
    }
    .stat-card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1.25rem;
    }
    .stat-label { font-size: 0.75rem; text-transform: uppercase; color: #64748b; font-weight: 600; }
    .stat-val { font-size: 1.5rem; font-weight: 700; margin-top: 0.25rem; }
    code {
      font-family: monospace;
      background: #f1f5f9;
      padding: 0.15rem 0.35rem;
      border-radius: 4px;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div>
        <h1>CodeGuard Quality Gate</h1>
        <div style="color: #64748b; font-size: 0.875rem; margin-top: 0.25rem;">
          Fail-on: <strong>{{ report.fail_on.value }}</strong> |
          Exit: <strong>{{ report.exit_code() }}</strong>
        </div>
      </div>
      <div>
        {% if report.exit_code() == 0 %}
          <span class="badge badge-PASS">PASSED</span>
        {% elif report.exit_code() == 1 %}
          <span class="badge badge-FAIL">FAILED</span>
        {% else %}
          <span class="badge badge-ERROR">TOOL ERROR</span>
        {% endif %}
      </div>
    </div>

    <div class="stats">
      <div class="stat-card">
        <div class="stat-label">Total Checks</div>
        <div class="stat-val">{{ report.results|length }}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Total Findings</div>
        <div class="stat-val">{{ total_findings }}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Tests (Pass/Fail/Skip)</div>
        <div class="stat-val">{{ total_tests_p }} / {{ total_tests_f }} / {{ total_tests_s }}</div>
      </div>
    </div>

    <div class="card">
      <h2>Check Results</h2>
      <table>
        <thead>
          <tr>
            <th>Check</th>
            <th>Status</th>
            <th>Findings</th>
            <th>Tests</th>
            <th>Duration</th>
            <th>Error</th>
          </tr>
        </thead>
        <tbody>
          {% for r in report.results %}
            {% set has_failed = r.failed_tests > 0 %}
            {% set status = "ERROR" if r.error else ("FAIL" if has_failed else "PASS") %}
            <tr>
              <td><strong>{{ r.check }}</strong></td>
              <td><span class="badge badge-{{ status }}">{{ status }}</span></td>
              <td>{{ r.findings|length }}</td>
              <td>{{ r.passed_tests }} pass, {{ r.failed_tests }} fail, {{ r.skipped_tests }}</td>
              <td>{{ "%.1f"|format(r.duration_ms) }} ms</td>
              <td>
                {% if r.error %}
                  <span style="color: var(--fail);">{{ r.error }}</span>
                {% else %}
                  -
                {% endif %}
              </td>
            </tr>
          {% endfor %}
        </tbody>
      </table>
    </div>

    {% if total_findings > 0 %}
    <div class="card">
      <h2>Findings Detail</h2>
      <table>
        <thead>
          <tr>
            <th>Severity</th>
            <th>Check</th>
            <th>Rule ID</th>
            <th>File:Line</th>
            <th>Message</th>
          </tr>
        </thead>
        <tbody>
          {% for r in report.results %}
            {% for f in r.findings %}
              <tr>
                <td>
                  <span class="badge badge-{{ f.severity.value }}">{{ f.severity.value }}</span>
                </td>
                <td>{{ f.check }}</td>
                <td><code>{{ f.rule_id }}</code></td>
                <td>
                  {% if f.file and f.line %}
                    {{ f.file }}:{{ f.line }}
                  {% elif f.file %}
                    {{ f.file }}
                  {% else %}
                    -
                  {% endif %}
                </td>
                <td>{{ f.message }}</td>
              </tr>
            {% endfor %}
          {% endfor %}
        </tbody>
      </table>
    </div>
    {% endif %}
  </div>
</body>
</html>
"""


def get_status_str(result: CheckResult, report: Report) -> str:
    """Return status string for a CheckResult: PASS, FAIL, or ERROR."""
    if result.error:
        return "ERROR"
    if result.failed_tests > 0 or any(f.severity.at_least(report.fail_on) for f in result.findings):
        return "FAIL"
    return "PASS"


def render_console(report: Report, console: Console | None = None) -> None:
    """Render rich table and plain text summary to console/stdout."""
    c = console if console is not None else Console(file=sys.stdout)

    if not report.results:
        c.print("No checks ran.")
        c.print(f"exit: {report.exit_code()}")
        return

    table = Table(
        title="CodeGuard Quality Gate Results", show_header=True, header_style="bold cyan"
    )
    table.add_column("Check", style="bold")
    table.add_column("Status")
    table.add_column("Findings", justify="right")
    table.add_column("Tests (P/F/S)", justify="center")
    table.add_column("Duration (ms)", justify="right")
    table.add_column("Error")

    for r in report.results:
        status = get_status_str(r, report)
        if status == "PASS":
            status_text = Text(status, style="bold green")
        elif status == "FAIL":
            status_text = Text(status, style="bold red")
        else:
            status_text = Text(status, style="bold magenta")

        tests_str = f"{r.passed_tests}/{r.failed_tests}/{r.skipped_tests}"
        duration_str = f"{r.duration_ms:.1f}"
        error_str = r.error or "-"
        table.add_row(
            r.check, status_text, str(len(r.findings)), tests_str, duration_str, error_str
        )

    c.print(table)

    # Detailed findings
    for r in report.results:
        status = get_status_str(r, report)
        c.print(
            f"{r.check}: {status} findings={len(r.findings)} "
            f"tests={r.passed_tests} passed, {r.failed_tests} failed, {r.skipped_tests} skipped"
        )
        if r.error:
            c.print(f"  error: {r.error}")
        for f in r.findings:
            loc = f"{f.file}:{f.line}" if f.file and f.line else (f.file or "-")
            c.print(f"  [{f.severity.value}] {f.rule_id} {loc} {f.message}")

    c.print(f"exit: {report.exit_code()}")


def generate_markdown(report: Report) -> str:
    """Return a Markdown report."""
    status_label = (
        "PASSED" if report.exit_code() == 0 else ("FAILED" if report.exit_code() == 1 else "ERROR")
    )
    lines: list[str] = [
        "# CodeGuard Quality Gate Report",
        "",
        f"**Gate Status:** {status_label} | "
        f"**Fail-On:** `{report.fail_on.value}` | "
        f"**Exit Code:** `{report.exit_code()}`",
        "",
        "## Summary",
        "",
        "| Check | Status | Findings | Tests (Pass/Fail/Skip) | Duration | Error |",
        "| :--- | :---: | :---: | :---: | :---: | :--- |",
    ]

    for r in report.results:
        status = get_status_str(r, report)
        tests_str = f"{r.passed_tests} / {r.failed_tests} / {r.skipped_tests}"
        err = r.error.replace("\n", " ") if r.error else "-"
        dur = f"{r.duration_ms:.1f}ms"
        lines.append(f"| {r.check} | {status} | {len(r.findings)} | {tests_str} | {dur} | {err} |")

    # Findings section
    all_findings: list[Finding] = [f for r in report.results for f in r.findings]
    if all_findings:
        lines.extend(
            [
                "",
                "## Findings",
                "",
                "| Severity | Check | Rule ID | Location | Message |",
                "| :--- | :--- | :--- | :--- | :--- |",
            ]
        )
        for f in all_findings:
            loc = f"{f.file}:{f.line}" if f.file and f.line else (f.file or "-")
            lines.append(
                f"| **{f.severity.value}** | {f.check} | `{f.rule_id}` | {loc} | {f.message} |"
            )

    lines.append("")
    return "\n".join(lines)


def generate_html(report: Report) -> str:
    """Return an HTML report rendered via Jinja2."""
    env = Environment(autoescape=select_autoescape(["html", "xml"]))
    template = env.from_string(_HTML_TEMPLATE)

    total_findings = sum(len(r.findings) for r in report.results)
    total_tests_p = sum(r.passed_tests for r in report.results)
    total_tests_f = sum(r.failed_tests for r in report.results)
    total_tests_s = sum(r.skipped_tests for r in report.results)

    return template.render(
        report=report,
        total_findings=total_findings,
        total_tests_p=total_tests_p,
        total_tests_f=total_tests_f,
        total_tests_s=total_tests_s,
    )


def generate_json(report: Report) -> str:
    """Return formatted JSON representation of the report."""
    return json.dumps(report.to_dict(), indent=2) + "\n"


def write_reports(report: Report, repo: Path, formats: tuple[str, ...]) -> list[Path]:
    """Write requested file reports to repo directory and return paths created."""
    written: list[Path] = []
    if "markdown" in formats:
        md_path = repo / "report.md"
        md_path.write_text(generate_markdown(report), encoding="utf-8")
        written.append(md_path)
    if "html" in formats:
        html_path = repo / "report.html"
        html_path.write_text(generate_html(report), encoding="utf-8")
        written.append(html_path)
    if "json" in formats:
        json_path = repo / "report.json"
        json_path.write_text(generate_json(report), encoding="utf-8")
        written.append(json_path)
    return written
