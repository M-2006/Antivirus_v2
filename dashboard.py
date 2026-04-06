"""
Flask web dashboard — runs at http://localhost:5000
Serves scan history from report.json as a clean HTML page + JSON API.
"""
from flask import Flask, jsonify, render_template_string
import json
import os

REPORT_FILE = "report.json"

app = Flask(__name__)

_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>Cyber Sentinel — Dashboard</title>
<style>
  :root {
    --bg: #0d0f14; --panel: #13161e; --border: #1e2330;
    --accent: #00e5ff; --text: #c8d6e5; --muted: #4a5568;
    --safe: #00e676; --warn: #ffab00; --danger: #ff1744;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: 'Courier New', monospace; padding: 24px; }
  h1 { color: var(--accent); font-size: 1.5rem; margin-bottom: 20px; }
  #summary { display: flex; gap: 20px; margin-bottom: 24px; flex-wrap: wrap; }
  .card { background: var(--panel); border: 1px solid var(--border); border-radius: 6px; padding: 16px 24px; min-width: 160px; }
  .card .label { font-size: 0.7rem; color: var(--muted); margin-bottom: 4px; }
  .card .value { font-size: 1.6rem; font-weight: bold; }
  table { width: 100%; border-collapse: collapse; background: var(--panel); border-radius: 6px; overflow: hidden; }
  th { background: var(--border); color: var(--muted); font-size: 0.75rem; padding: 10px 14px; text-align: left; }
  td { padding: 10px 14px; border-bottom: 1px solid var(--border); font-size: 0.8rem; }
  tr:last-child td { border-bottom: none; }
  .SAFE { color: var(--safe); } .SUSPICIOUS { color: var(--warn); } .MALICIOUS { color: var(--danger); }
  #refresh { margin-bottom: 16px; color: var(--muted); font-size: 0.75rem; }
  button { background: var(--accent); color: var(--bg); border: none; padding: 6px 14px; cursor: pointer;
           font-family: inherit; font-weight: bold; border-radius: 4px; margin-left: 10px; }
</style>
</head>
<body>
<h1>◈ CYBER SENTINEL — Web Dashboard</h1>
<div id="summary">
  <div class="card"><div class="label">TOTAL SCANS</div><div class="value" id="total">—</div></div>
  <div class="card"><div class="label">LAST VERDICT</div><div class="value" id="verdict">—</div></div>
  <div class="card"><div class="label">LAST SCORE</div><div class="value" id="score">—</div></div>
  <div class="card"><div class="label">FLAGGED</div><div class="value" id="flagged">—</div></div>
</div>
<div id="refresh">Auto-refreshes every 10s <button onclick="load()">Refresh Now</button></div>
<table>
  <thead><tr><th>#</th><th>Timestamp</th><th>Verdict</th><th>Score</th><th>Processes</th><th>Flagged</th><th>Findings</th></tr></thead>
  <tbody id="tbody"></tbody>
</table>
<script>
async function load() {
  const res = await fetch('/api/scans');
  const data = await res.json();
  const tbody = document.getElementById('tbody');
  tbody.innerHTML = '';
  if (!data.length) { tbody.innerHTML = '<tr><td colspan="7" style="color:var(--muted)">No scans yet.</td></tr>'; return; }
  const last = data[data.length - 1].result;
  document.getElementById('total').textContent = data.length;
  document.getElementById('verdict').className = 'value ' + last.verdict;
  document.getElementById('verdict').textContent = last.verdict;
  document.getElementById('score').textContent = last.score + ' / 100';
  document.getElementById('flagged').textContent = (last.flagged_pids || []).length;
  [...data].reverse().forEach((entry, i) => {
    const r = entry.result;
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${data.length - i}</td>
      <td>${entry.timestamp}</td>
      <td class="${r.verdict}">${r.verdict}</td>
      <td>${r.score}</td>
      <td>${r.total_processes}</td>
      <td>${(r.flagged_pids || []).length}</td>
      <td style="font-size:0.72rem;color:var(--muted)">${(r.findings || []).slice(0,3).join(' | ') || '—'}</td>`;
    tbody.appendChild(tr);
  });
}
load();
setInterval(load, 10000);
</script>
</body>
</html>
"""

@app.route("/")
def index():
    return render_template_string(_HTML)


@app.route("/api/scans")
def api_scans():
    if not os.path.exists(REPORT_FILE):
        return jsonify([])
    try:
        with open(REPORT_FILE) as f:
            data = json.load(f)
        if not isinstance(data, list):
            data = [data]
        return jsonify(data)
    except Exception:
        return jsonify([])


@app.route("/api/latest")
def api_latest():
    if not os.path.exists(REPORT_FILE):
        return jsonify({})
    try:
        with open(REPORT_FILE) as f:
            data = json.load(f)
        if isinstance(data, list) and data:
            return jsonify(data[-1])
        return jsonify({})
    except Exception:
        return jsonify({})


if __name__ == "__main__":
    app.run(port=5000, debug=True)
