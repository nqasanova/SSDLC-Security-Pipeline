"""
dashboard/dashboard_generator.py
Generates a self-contained HTML security dashboard with:
  - Severity summary cards
  - Findings by tool (bar chart via Chart.js CDN)
  - Historical vulnerability trend (line chart)
  - Sortable/filterable findings table
"""

import json
import os
from datetime import datetime
from typing import List, Dict, Any


SEVERITY_COLOR = {
    "CRITICAL": "#dc2626",
    "HIGH":     "#ea580c",
    "MEDIUM":   "#d97706",
    "LOW":      "#2563eb",
}


class DashboardGenerator:
    def __init__(
        self,
        findings: List[Dict[str, Any]],
        metrics_history: List[Dict[str, Any]],
        output_dir: str,
    ):
        self.findings = findings
        self.metrics_history = metrics_history
        self.output_dir = output_dir
        self.timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    def generate(self) -> None:
        path = os.path.join(self.output_dir, "dashboard.html")
        html = self._build_html()
        with open(path, "w") as fh:
            fh.write(html)

    # ------------------------------------------------------------------
    def _build_html(self) -> str:
        counts = self._count_by_severity()
        by_tool = self._count_by_tool()
        findings_json = json.dumps(self.findings, indent=2)
        history_labels = [e["timestamp"][:10] for e in self.metrics_history]
        history_high = [e["counts"].get("HIGH", 0) + e["counts"].get("CRITICAL", 0)
                        for e in self.metrics_history]
        history_medium = [e["counts"].get("MEDIUM", 0) for e in self.metrics_history]
        history_low = [e["counts"].get("LOW", 0) for e in self.metrics_history]

        tool_labels = json.dumps(list(by_tool.keys()))
        tool_data   = json.dumps(list(by_tool.values()))

        rows = ""
        for f in sorted(self.findings,
                         key=lambda x: {"CRITICAL":4,"HIGH":3,"MEDIUM":2,"LOW":1}
                         .get(x.get("severity","LOW").upper(), 0),
                         reverse=True):
            sev = f.get("severity", "LOW").upper()
            color = SEVERITY_COLOR.get(sev, "#6b7280")
            rows += f"""
            <tr>
              <td><span class="badge" style="background:{color}">{sev}</span></td>
              <td><code>{f.get('rule_id','')}</code></td>
              <td>{f.get('rule_name', f.get('rule_id',''))}</td>
              <td><code>{os.path.basename(f.get('file',''))}</code></td>
              <td>{f.get('line','')}</td>
              <td>{f.get('tool','')}</td>
              <td class="msg">{f.get('message','')[:120]}{'…' if len(f.get('message',''))>120 else ''}</td>
            </tr>"""

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>SSDLC Security Dashboard</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
  <style>
    *, *::before, *::after {{ box-sizing: border-box; margin:0; padding:0; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
            background:#0f172a; color:#e2e8f0; min-height:100vh; }}
    header {{ background:#1e293b; border-bottom:1px solid #334155;
              padding:1.25rem 2rem; display:flex; align-items:center; gap:1rem; }}
    header h1 {{ font-size:1.4rem; font-weight:700; color:#f1f5f9; }}
    header .ts {{ margin-left:auto; font-size:.8rem; color:#94a3b8; }}
    .container {{ max-width:1400px; margin:0 auto; padding:2rem; }}

    /* Summary cards */
    .cards {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr));
              gap:1rem; margin-bottom:2rem; }}
    .card {{ background:#1e293b; border-radius:.75rem; padding:1.25rem;
             text-align:center; border:1px solid #334155; }}
    .card .count {{ font-size:2.5rem; font-weight:800; }}
    .card .label {{ font-size:.8rem; color:#94a3b8; margin-top:.25rem; text-transform:uppercase; letter-spacing:.05em; }}
    .card.critical .count {{ color:#dc2626; }}
    .card.high .count    {{ color:#ea580c; }}
    .card.medium .count  {{ color:#d97706; }}
    .card.low .count     {{ color:#2563eb; }}
    .card.total .count   {{ color:#f1f5f9; }}

    /* Charts grid */
    .charts {{ display:grid; grid-template-columns:1fr 1fr; gap:1.5rem; margin-bottom:2rem; }}
    @media(max-width:900px){{ .charts{{ grid-template-columns:1fr; }} }}
    .chart-box {{ background:#1e293b; border-radius:.75rem; padding:1.5rem;
                  border:1px solid #334155; }}
    .chart-box h2 {{ font-size:1rem; font-weight:600; color:#f1f5f9; margin-bottom:1rem; }}
    canvas {{ max-height:260px; }}

    /* Findings table */
    .table-box {{ background:#1e293b; border-radius:.75rem; padding:1.5rem;
                  border:1px solid #334155; overflow-x:auto; }}
    .table-header {{ display:flex; align-items:center; justify-content:space-between;
                     margin-bottom:1rem; flex-wrap:wrap; gap:.5rem; }}
    .table-header h2 {{ font-size:1rem; font-weight:600; color:#f1f5f9; }}
    #search {{ background:#0f172a; border:1px solid #475569; border-radius:.5rem;
               color:#e2e8f0; padding:.4rem .75rem; font-size:.85rem; width:240px; }}
    #sev-filter {{ background:#0f172a; border:1px solid #475569; border-radius:.5rem;
                   color:#e2e8f0; padding:.4rem .75rem; font-size:.85rem; }}
    table {{ width:100%; border-collapse:collapse; font-size:.82rem; }}
    th {{ text-align:left; padding:.6rem .75rem; color:#94a3b8;
          border-bottom:1px solid #334155; white-space:nowrap; cursor:pointer; }}
    th:hover {{ color:#f1f5f9; }}
    td {{ padding:.55rem .75rem; border-bottom:1px solid #1e293b; vertical-align:top; }}
    tr:hover td {{ background:#263548; }}
    .badge {{ display:inline-block; padding:.15rem .5rem; border-radius:.35rem;
              font-size:.7rem; font-weight:700; color:#fff; white-space:nowrap; }}
    .msg {{ color:#94a3b8; max-width:400px; }}
    code {{ background:#0f172a; padding:.1rem .35rem; border-radius:.25rem;
            font-size:.78rem; color:#7dd3fc; }}
    .empty {{ text-align:center; padding:3rem; color:#475569; font-size:.95rem; }}
  </style>
</head>
<body>
<header>
  <div>🔒</div>
  <h1>SSDLC Security Dashboard</h1>
  <span class="ts">Generated: {self.timestamp}</span>
</header>
<div class="container">

  <!-- Summary cards -->
  <div class="cards">
    <div class="card total">
      <div class="count">{len(self.findings)}</div>
      <div class="label">Total Findings</div>
    </div>
    <div class="card critical">
      <div class="count">{counts.get('CRITICAL',0)}</div>
      <div class="label">Critical</div>
    </div>
    <div class="card high">
      <div class="count">{counts.get('HIGH',0)}</div>
      <div class="label">High</div>
    </div>
    <div class="card medium">
      <div class="count">{counts.get('MEDIUM',0)}</div>
      <div class="label">Medium</div>
    </div>
    <div class="card low">
      <div class="count">{counts.get('LOW',0)}</div>
      <div class="label">Low</div>
    </div>
  </div>

  <!-- Charts -->
  <div class="charts">
    <div class="chart-box">
      <h2>📊 Findings by Tool</h2>
      <canvas id="toolChart"></canvas>
    </div>
    <div class="chart-box">
      <h2>📈 Vulnerability Trend</h2>
      <canvas id="trendChart"></canvas>
    </div>
  </div>

  <!-- Findings table -->
  <div class="table-box">
    <div class="table-header">
      <h2>🔍 Findings ({len(self.findings)})</h2>
      <div style="display:flex;gap:.5rem;flex-wrap:wrap;">
        <select id="sev-filter" onchange="applyFilters()">
          <option value="">All severities</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="LOW">Low</option>
        </select>
        <input id="search" type="text" placeholder="Search rule / file / message…"
               oninput="applyFilters()"/>
      </div>
    </div>
    {"<p class='empty'>✅ No confirmed findings — great job!</p>" if not self.findings else f'''
    <table id="findings-table">
      <thead>
        <tr>
          <th onclick="sortTable(0)">Severity ↕</th>
          <th onclick="sortTable(1)">Rule ID ↕</th>
          <th onclick="sortTable(2)">Name ↕</th>
          <th onclick="sortTable(3)">File ↕</th>
          <th onclick="sortTable(4)">Line ↕</th>
          <th onclick="sortTable(5)">Tool ↕</th>
          <th>Message</th>
        </tr>
      </thead>
      <tbody id="tbody">{rows}</tbody>
    </table>'''}
  </div>
</div>

<script>
// ----- Charts -----
const toolCtx = document.getElementById('toolChart');
if (toolCtx) {{
  new Chart(toolCtx, {{
    type: 'bar',
    data: {{
      labels: {tool_labels},
      datasets: [{{
        label: 'Findings',
        data: {tool_data},
        backgroundColor: ['#3b82f6','#8b5cf6','#06b6d4','#10b981'],
        borderRadius: 6,
      }}]
    }},
    options: {{
      responsive: true,
      plugins: {{ legend: {{ display: false }} }},
      scales: {{
        x: {{ ticks: {{ color:'#94a3b8' }}, grid: {{ color:'#1e293b' }} }},
        y: {{ ticks: {{ color:'#94a3b8' }}, grid: {{ color:'#334155' }}, beginAtZero:true }}
      }}
    }}
  }});
}}

const trendCtx = document.getElementById('trendChart');
if (trendCtx) {{
  new Chart(trendCtx, {{
    type: 'line',
    data: {{
      labels: {json.dumps(history_labels)},
      datasets: [
        {{
          label: 'High/Critical',
          data: {json.dumps(history_high)},
          borderColor: '#ea580c',
          backgroundColor: 'rgba(234,88,12,.15)',
          fill: true, tension:.3, pointRadius:4,
        }},
        {{
          label: 'Medium',
          data: {json.dumps(history_medium)},
          borderColor: '#d97706',
          backgroundColor: 'rgba(217,119,6,.1)',
          fill: true, tension:.3, pointRadius:4,
        }},
        {{
          label: 'Low',
          data: {json.dumps(history_low)},
          borderColor: '#2563eb',
          backgroundColor: 'rgba(37,99,235,.1)',
          fill: true, tension:.3, pointRadius:4,
        }},
      ]
    }},
    options: {{
      responsive: true,
      plugins: {{ legend: {{ labels: {{ color:'#94a3b8' }} }} }},
      scales: {{
        x: {{ ticks: {{ color:'#94a3b8' }}, grid: {{ color:'#1e293b' }} }},
        y: {{ ticks: {{ color:'#94a3b8' }}, grid: {{ color:'#334155' }}, beginAtZero:true }}
      }}
    }}
  }});
}}

// ----- Table filtering -----
function applyFilters() {{
  const q = document.getElementById('search').value.toLowerCase();
  const sev = document.getElementById('sev-filter').value.toUpperCase();
  document.querySelectorAll('#tbody tr').forEach(row => {{
    const text = row.innerText.toLowerCase();
    const sevCell = row.cells[0] ? row.cells[0].innerText.trim().toUpperCase() : '';
    const sevMatch = !sev || sevCell === sev;
    const textMatch = !q || text.includes(q);
    row.style.display = (sevMatch && textMatch) ? '' : 'none';
  }});
}}

// ----- Table sorting -----
let sortDir = {{}};
function sortTable(col) {{
  const tbody = document.getElementById('tbody');
  if (!tbody) return;
  const rows = Array.from(tbody.rows);
  const asc = !sortDir[col];
  sortDir[col] = asc;
  rows.sort((a,b) => {{
    const va = a.cells[col]?.innerText.trim() || '';
    const vb = b.cells[col]?.innerText.trim() || '';
    return asc ? va.localeCompare(vb) : vb.localeCompare(va);
  }});
  rows.forEach(r => tbody.appendChild(r));
}}
</script>
</body>
</html>"""

    def _count_by_severity(self) -> Dict[str, int]:
        counts: Dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in self.findings:
            sev = f.get("severity", "LOW").upper()
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    def _count_by_tool(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for f in self.findings:
            tool = f.get("tool", "unknown")
            counts[tool] = counts.get(tool, 0) + 1
        return counts
