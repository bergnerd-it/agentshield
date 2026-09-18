"""Self-contained, privacy-preserving HTML audit report exporter."""

import html
import json
from datetime import UTC, datetime
from typing import Any

from agentshield import __version__


def export_html(
    events: list[dict[str, Any]],
    filters: dict[str, Any] | None = None,
) -> str:
    """Generate a self-contained, standalone HTML audit report without CDN dependencies."""
    now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
    active_filters = {k: v for k, v in (filters or {}).items() if v is not None}

    # Compute summary metrics
    total_events = len(events)
    blocked_count = sum(1 for e in events if e.get("action") == "BLOCK")
    redacted_count = sum(1 for e in events if e.get("action") == "REDACT")
    approval_count = sum(1 for e in events if e.get("action") == "REQUIRE_APPROVAL")
    allowed_count = sum(1 for e in events if e.get("action") in ("ALLOW", "WARN"))

    durations: list[float] = []
    for e in events:
        meta = e.get("metadata") or {}
        if "duration_ms" in meta and isinstance(meta["duration_ms"], (int, float)):
            durations.append(float(meta["duration_ms"]))
    avg_duration = round(sum(durations) / len(durations), 1) if durations else 0.0

    # Build rows HTML
    rows_html: list[str] = []
    for idx, e in enumerate(events):
        event_id = html.escape(str(e.get("id", "")))
        timestamp = html.escape(str(e.get("timestamp", ""))[:19].replace("T", " "))
        action = html.escape(str(e.get("action", "UNKNOWN")))
        provider = html.escape(str(e.get("provider", "")))
        model = html.escape(str(e.get("model") or "-"))
        agent = html.escape(str(e.get("agent") or "-"))
        project = html.escape(str(e.get("project") or "-"))
        endpoint = html.escape(str(e.get("endpoint", "")))
        rule_id = html.escape(str(e.get("rule_id") or "-"))

        meta = e.get("metadata") or {}
        status_code = html.escape(str(meta.get("status_code", "-")))
        dur = html.escape(str(meta.get("duration_ms", "-")))
        req_size = html.escape(str(meta.get("request_size", "-")))
        resp_size = html.escape(str(meta.get("response_size", "-")))
        fingerprint = html.escape(str(meta.get("sha256_fingerprint", "-")))
        overhead = html.escape(str(meta.get("proxy_overhead_ms", "-")))

        finding_counts = e.get("finding_counts") or {}
        findings_str = (
            ", ".join(f"{k}: {v}" for k, v in finding_counts.items()) if finding_counts else "None"
        )
        findings_escaped = html.escape(findings_str)

        action_cls = {
            "BLOCK": "badge-block",
            "REDACT": "badge-redact",
            "REQUIRE_APPROVAL": "badge-approval",
            "WARN": "badge-warn",
            "ALLOW": "badge-allow",
        }.get(action, "badge-unknown")

        safe_details = {
            "id": e.get("id"),
            "request_id": e.get("request_id"),
            "session_id": e.get("session_id"),
            "rule_id": e.get("rule_id"),
            "finding_counts": finding_counts,
            "metadata": meta,
        }
        details_json = html.escape(json.dumps(safe_details, indent=2, ensure_ascii=False))

        rows_html.append(
            f"""
        <tr class="audit-row" onclick="toggleDetails('{idx}')">
          <td class="cell-mono">{timestamp}</td>
          <td><span class="badge {action_cls}">{action}</span></td>
          <td>{provider}</td>
          <td>{model}</td>
          <td>{agent}</td>
          <td class="cell-mono">{endpoint}</td>
          <td class="cell-num">{status_code}</td>
          <td class="cell-num">{dur}ms</td>
          <td>{findings_escaped}</td>
          <td><button type="button" class="btn-sm" aria-label="Toggle">Inspect</button></td>
        </tr>
        <tr id="details-{idx}" class="details-row" style="display: none;">
          <td colspan="10">
            <div class="details-panel">
              <div class="details-grid">
                <div><strong>Event ID:</strong> <code>{event_id}</code></div>
                <div><strong>Project:</strong> {project}</div>
                <div><strong>Request Bytes:</strong> {req_size}</div>
                <div><strong>Response Bytes:</strong> {resp_size}</div>
                <div><strong>Proxy Overhead:</strong> {overhead}ms</div>
                <div><strong>Policy Rule:</strong> <code>{rule_id}</code></div>
                <div class="col-span-2">
                  <strong>Normalized Content SHA-256:</strong> <code>{fingerprint}</code>
                </div>
              </div>
              <div class="details-json-wrapper">
                <strong>Sanitized Metadata:</strong>
                <pre><code>{details_json}</code></pre>
              </div>
            </div>
          </td>
        </tr>"""
        )

    filters_desc = (
        ", ".join(f"{k}='{v}'" for k, v in active_filters.items())
        if active_filters
        else "All historical records"
    )

    empty_row = (
        '<tr><td colspan="10" style="text-align: center; padding: 2rem; color: #94a3b8;">'
        "No audit events matching criteria.</td></tr>"
    )
    rows_joined = "".join(rows_html) if rows_html else empty_row

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AgentShield Audit Report - {now}</title>
  <style>
    :root {{
      --bg: #0f172a;
      --card-bg: #1e293b;
      --border: #334155;
      --text: #f8fafc;
      --text-muted: #94a3b8;
      --primary: #38bdf8;
      --block: #ef4444;
      --redact: #f59e0b;
      --approval: #a855f7;
      --allow: #10b981;
      --warn: #eab308;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background-color: var(--bg);
      color: var(--text);
      padding: 2rem;
      line-height: 1.5;
    }}
    .container {{ max-width: 1400px; margin: 0 auto; }}
    header {{
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      margin-bottom: 2rem;
      border-bottom: 1px solid var(--border);
      padding-bottom: 1.5rem;
    }}
    h1 {{
      font-size: 1.875rem;
      font-weight: 700;
      color: var(--primary);
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }}
    .subtitle {{ color: var(--text-muted); font-size: 0.875rem; margin-top: 0.25rem; }}
    .notice-banner {{
      background: rgba(56, 189, 248, 0.1);
      border: 1px solid rgba(56, 189, 248, 0.3);
      border-radius: 0.5rem;
      padding: 1rem 1.25rem;
      margin-bottom: 2rem;
      display: flex;
      align-items: center;
      gap: 0.75rem;
      font-size: 0.9375rem;
      color: #e0f2fe;
    }}
    .metrics-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 1rem;
      margin-bottom: 2rem;
    }}
    .metric-card {{
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 0.5rem;
      padding: 1.25rem;
      text-align: center;
    }}
    .metric-value {{ font-size: 2rem; font-weight: 700; color: var(--text); }}
    .metric-label {{
      font-size: 0.8125rem;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }}
    .table-container {{
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 0.5rem;
      overflow-x: auto;
    }}
    table {{ width: 100%; border-collapse: collapse; text-align: left; font-size: 0.875rem; }}
    th {{
      background: #0f172a;
      padding: 0.875rem 1rem;
      font-weight: 600;
      color: var(--text-muted);
      border-bottom: 1px solid var(--border);
    }}
    td {{
      padding: 0.875rem 1rem;
      border-bottom: 1px solid var(--border);
      vertical-align: middle;
    }}
    .audit-row:hover {{ background: rgba(255, 255, 255, 0.03); cursor: pointer; }}
    .cell-mono {{
      font-family: ui-monospace, Menlo, Monaco, Consolas, monospace;
      font-size: 0.8rem;
    }}
    .cell-num {{ font-variant-numeric: tabular-nums; }}
    .badge {{
      display: inline-block;
      padding: 0.2rem 0.5rem;
      border-radius: 9999px;
      font-size: 0.75rem;
      font-weight: 600;
    }}
    .badge-block {{
      background: rgba(239, 68, 68, 0.2);
      color: var(--block);
      border: 1px solid rgba(239, 68, 68, 0.4);
    }}
    .badge-redact {{
      background: rgba(245, 158, 11, 0.2);
      color: var(--redact);
      border: 1px solid rgba(245, 158, 11, 0.4);
    }}
    .badge-approval {{
      background: rgba(168, 85, 247, 0.2);
      color: var(--approval);
      border: 1px solid rgba(168, 85, 247, 0.4);
    }}
    .badge-warn {{
      background: rgba(234, 179, 8, 0.2);
      color: var(--warn);
      border: 1px solid rgba(234, 179, 8, 0.4);
    }}
    .badge-allow {{
      background: rgba(16, 185, 129, 0.2);
      color: var(--allow);
      border: 1px solid rgba(16, 185, 129, 0.4);
    }}
    .btn-sm {{
      background: transparent;
      border: 1px solid var(--border);
      color: var(--primary);
      border-radius: 0.25rem;
      padding: 0.25rem 0.5rem;
      font-size: 0.75rem;
      cursor: pointer;
    }}
    .btn-sm:hover {{ background: rgba(56, 189, 248, 0.1); border-color: var(--primary); }}
    .details-row {{ background: #0c1322; }}
    .details-panel {{ padding: 1.25rem; border-left: 3px solid var(--primary); }}
    .details-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
      gap: 0.75rem;
      margin-bottom: 1rem;
      font-size: 0.8125rem;
    }}
    .col-span-2 {{ grid-column: span 2; }}
    code {{
      background: rgba(255, 255, 255, 0.08);
      padding: 0.15rem 0.35rem;
      border-radius: 0.25rem;
      font-family: monospace;
      font-size: 0.8em;
    }}
    .details-json-wrapper {{ margin-top: 0.5rem; }}
    pre {{
      background: #060b13;
      padding: 0.75rem;
      border-radius: 0.375rem;
      overflow-x: auto;
      font-size: 0.75rem;
      margin-top: 0.25rem;
      border: 1px solid var(--border);
    }}
    footer {{
      margin-top: 3rem;
      text-align: center;
      font-size: 0.8125rem;
      color: var(--text-muted);
      border-top: 1px solid var(--border);
      padding-top: 1.5rem;
    }}
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div>
        <h1>🛡️ AgentShield Audit Report</h1>
        <p class="subtitle">Generated on {now} - AgentShield v{__version__}</p>
        <p class="subtitle">Active Filters: {html.escape(filters_desc)}</p>
      </div>
    </header>

    <div class="notice-banner">
      <span>🔒</span>
      <div>
        <strong>Privacy-Preserving Audit Guarantee:</strong>
        This report contains only decision metadata, technical metrics, and content fingerprints.
        Raw prompts, upstream responses, and detected secrets are excluded by design (ADR 0004).
      </div>
    </div>

    <div class="metrics-grid">
      <div class="metric-card">
        <div class="metric-value">{total_events}</div>
        <div class="metric-label">Total Events</div>
      </div>
      <div class="metric-card">
        <div class="metric-value" style="color: var(--block);">{blocked_count}</div>
        <div class="metric-label">Blocked</div>
      </div>
      <div class="metric-card">
        <div class="metric-value" style="color: var(--redact);">{redacted_count}</div>
        <div class="metric-label">Redacted</div>
      </div>
      <div class="metric-card">
        <div class="metric-value" style="color: var(--approval);">{approval_count}</div>
        <div class="metric-label">Manual Approvals</div>
      </div>
      <div class="metric-card">
        <div class="metric-value" style="color: var(--allow);">{allowed_count}</div>
        <div class="metric-label">Allowed / Warned</div>
      </div>
      <div class="metric-card">
        <div class="metric-value">{avg_duration}ms</div>
        <div class="metric-label">Avg Duration</div>
      </div>
    </div>

    <div class="table-container">
      <table>
        <thead>
          <tr>
            <th>Timestamp</th>
            <th>Action</th>
            <th>Provider</th>
            <th>Model</th>
            <th>Agent</th>
            <th>Endpoint</th>
            <th>Status</th>
            <th>Duration</th>
            <th>Findings</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {rows_joined}
        </tbody>
      </table>
    </div>

    <footer>
      AgentShield - Local Security Proxy for Coding Agents - Standalone Offline Audit Report
    </footer>
  </div>

  <script>
    function toggleDetails(id) {{
      var row = document.getElementById('details-' + id);
      if (row) {{
        row.style.display = row.style.display === 'none' ? 'table-row' : 'none';
      }}
    }}
  </script>
</body>
</html>"""
