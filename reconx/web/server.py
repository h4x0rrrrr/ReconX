"""ReconX Built-in Interactive Web GUI & REST API Server.

Serves an interactive web dashboard for launching scans, monitoring live execution,
and browsing historical reports and intelligence artifacts.
"""
from __future__ import annotations

import io
import json
import mimetypes
import os
import subprocess
import sys
import threading
import time
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from reconx.utils.logger import info, warn

# Background Task Storage
ACTIVE_TASKS: dict[str, dict] = {}
OUTPUT_BASE = os.path.abspath("recon_output")

HTML_DASHBOARD = r"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>ReconX — Red-Team Reconnaissance Dashboard</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg: #07090e;
      --card-bg: #0f141f;
      --card-border: #1a2234;
      --text-main: #f1f5f9;
      --text-dim: #94a3b8;
      --accent-cyan: #00ffc8;
      --accent-blue: #38bdf8;
      --accent-indigo: #6366f1;
      --accent-red: #f43f5e;
      --accent-green: #10b981;
      --accent-yellow: #f59e0b;
      --mono-font: 'JetBrains Mono', monospace;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background-color: var(--bg);
      color: var(--text-main);
      font-family: 'Plus Jakarta Sans', sans-serif;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
    }
    header {
      background: rgba(15, 20, 31, 0.85);
      backdrop-filter: blur(12px);
      border-bottom: 1px solid var(--card-border);
      padding: 1rem 2rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
      position: sticky;
      top: 0;
      z-index: 50;
    }
    .brand {
      display: flex;
      align-items: center;
      gap: 0.75rem;
      font-weight: 800;
      font-size: 1.25rem;
      letter-spacing: -0.025em;
    }
    .brand-badge {
      background: linear-gradient(135deg, #00ffc8 0%, #38bdf8 100%);
      color: #07090e;
      font-size: 0.7rem;
      font-weight: 800;
      padding: 0.2rem 0.5rem;
      border-radius: 4px;
      font-family: var(--mono-font);
    }
    .container {
      max-width: 1300px;
      width: 100%;
      margin: 2rem auto;
      padding: 0 1.5rem;
      flex: 1;
      display: grid;
      grid-template-columns: 380px 1fr;
      gap: 2rem;
    }
    @media (max-width: 900px) {
      .container { grid-template-columns: 1fr; }
    }
    .card {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 12px;
      padding: 1.5rem;
      box-shadow: 0 8px 30px rgba(0,0,0,0.4);
    }
    .card-title {
      font-size: 1.1rem;
      font-weight: 700;
      margin-bottom: 1rem;
      display: flex;
      align-items: center;
      gap: 0.5rem;
      color: var(--text-main);
      border-bottom: 1px solid var(--card-border);
      padding-bottom: 0.75rem;
    }
    label {
      display: block;
      font-size: 0.8rem;
      font-weight: 600;
      color: var(--text-dim);
      margin-top: 0.85rem;
      margin-bottom: 0.35rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }
    input, select {
      width: 100%;
      background: #090c13;
      border: 1px solid var(--card-border);
      color: var(--text-main);
      padding: 0.65rem 0.85rem;
      border-radius: 8px;
      font-family: var(--mono-font);
      font-size: 0.9rem;
      outline: none;
      transition: border-color 0.2s;
    }
    input:focus, select:focus {
      border-color: var(--accent-cyan);
    }
    .checkbox-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 0.6rem;
      margin-top: 0.75rem;
      background: #080b11;
      padding: 0.85rem;
      border-radius: 8px;
      border: 1px solid var(--card-border);
    }
    .checkbox-item {
      display: flex;
      align-items: center;
      gap: 0.4rem;
      font-size: 0.8rem;
      color: var(--text-main);
    }
    .checkbox-item input {
      width: auto;
      margin: 0;
      accent-color: var(--accent-cyan);
    }
    .btn {
      width: 100%;
      background: linear-gradient(135deg, #00ffc8 0%, #38bdf8 100%);
      color: #07090e;
      border: none;
      font-weight: 700;
      font-size: 0.95rem;
      padding: 0.85rem;
      border-radius: 8px;
      cursor: pointer;
      margin-top: 1.5rem;
      transition: transform 0.15s, opacity 0.15s;
    }
    .btn:hover { opacity: 0.9; transform: translateY(-1px); }
    .btn:disabled { opacity: 0.4; cursor: not-allowed; }
    .status-panel {
      margin-top: 1.5rem;
      background: #07090f;
      border: 1px solid var(--card-border);
      border-radius: 8px;
      padding: 1rem;
      font-family: var(--mono-font);
      font-size: 0.8rem;
      min-height: 180px;
      max-height: 280px;
      overflow-y: auto;
      white-space: pre-wrap;
      color: #38bdf8;
    }
    .report-table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.85rem;
      margin-top: 1rem;
    }
    .report-table th {
      text-align: left;
      padding: 0.75rem;
      background: #090c13;
      color: var(--text-dim);
      border-bottom: 1px solid var(--card-border);
      font-weight: 600;
    }
    .report-table td {
      padding: 0.75rem;
      border-bottom: 1px solid var(--card-border);
      vertical-align: middle;
    }
    .report-table tr:hover td {
      background: rgba(255,255,255,0.02);
    }
    .badge {
      display: inline-block;
      padding: 0.2rem 0.5rem;
      border-radius: 4px;
      font-size: 0.75rem;
      font-weight: 600;
      font-family: var(--mono-font);
    }
    .badge-domain { background: rgba(56, 189, 248, 0.15); color: #38bdf8; border: 1px solid rgba(56, 189, 248, 0.3); }
    .badge-user { background: rgba(168, 85, 247, 0.15); color: #c084fc; border: 1px solid rgba(168, 85, 247, 0.3); }
    .link-btn {
      display: inline-flex;
      align-items: center;
      gap: 0.3rem;
      padding: 0.35rem 0.65rem;
      border-radius: 6px;
      background: rgba(0, 255, 200, 0.12);
      color: var(--accent-cyan);
      text-decoration: none;
      font-weight: 600;
      font-size: 0.78rem;
      transition: background 0.15s;
    }
    .link-btn:hover {
      background: rgba(0, 255, 200, 0.25);
    }
  </style>
</head>
<body>
  <header>
    <div class="brand">
      <span>⚡ ReconX Web Platform</span>
      <span class="brand-badge">v0.3.3 GUI</span>
    </div>
    <div style="font-size: 0.85rem; color: var(--text-dim);">
      Host: <strong style="color: var(--accent-cyan);" id="server-host">127.0.0.1:8080</strong>
    </div>
  </header>

  <div class="container">
    <!-- Left Column: Scan Controller -->
    <div>
      <div class="card">
        <h2 class="card-title">🚀 Launch Reconnaissance</h2>
        <form id="scan-form">
          <label for="mode">Recon Mode</label>
          <select id="mode" name="mode">
            <option value="domain" selected>Domain Recon (Infra, DNS, Ports, M365)</option>
            <option value="username">Username Recon (WhatsMyName, HIBP)</option>
            <option value="person">Person OSINT (Filtered Web Search)</option>
          </select>

          <label for="target">Target</label>
          <input type="text" id="target" name="target" placeholder="example.com or username" required>

          <label>Active Red-Team Flags (Domain Mode)</label>
          <div class="checkbox-grid">
            <div class="checkbox-item"><input type="checkbox" id="active" name="active" checked> <label for="active" style="margin:0;cursor:pointer;">Active Probe</label></div>
            <div class="checkbox-item"><input type="checkbox" id="takeovers" name="takeovers" checked> <label for="takeovers" style="margin:0;cursor:pointer;">Takeovers</label></div>
            <div class="checkbox-item"><input type="checkbox" id="buckets" name="buckets" checked> <label for="buckets" style="margin:0;cursor:pointer;">Buckets</label></div>
            <div class="checkbox-item"><input type="checkbox" id="security-headers" name="security-headers" checked> <label for="security-headers" style="margin:0;cursor:pointer;">Sec Headers</label></div>
            <div class="checkbox-item"><input type="checkbox" id="vhosts" name="vhosts"> <label for="vhosts" style="margin:0;cursor:pointer;">VHosts</label></div>
            <div class="checkbox-item"><input type="checkbox" id="ptr-sweep" name="ptr-sweep"> <label for="ptr-sweep" style="margin:0;cursor:pointer;">PTR Sweep</label></div>
          </div>

          <label for="threads">Concurrency Threads</label>
          <input type="number" id="threads" name="threads" value="8" min="1" max="32">

          <button type="submit" id="submit-btn" class="btn">⚡ Start Scan</button>
        </form>

        <label style="margin-top: 1.25rem;">Live Console Output</label>
        <div id="console-output" class="status-panel">System ready. Waiting for scan instructions...</div>
      </div>
    </div>

    <!-- Right Column: Historical Intelligence & Reports Hub -->
    <div>
      <div class="card">
        <div style="display:flex; justify-content:space-between; align-items:center;">
          <h2 class="card-title" style="margin:0;border:none;padding:0;">📁 Discovered Intelligence & Scan Reports</h2>
          <button onclick="loadScans()" style="background:none; border:1px solid var(--card-border); color:var(--text-dim); padding:0.3rem 0.6rem; border-radius:6px; cursor:pointer; font-size:0.8rem;">↻ Refresh</button>
        </div>
        <p style="font-size:0.85rem; color:var(--text-dim); margin-top:0.5rem;">Interactive HTML reports, CSV tables, and JSON datasets generated by ReconX:</p>

        <div style="overflow-x: auto;">
          <table class="report-table">
            <thead>
              <tr>
                <th>Target</th>
                <th>Mode</th>
                <th>Date / Time</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody id="scans-tbody">
              <tr><td colspan="4" style="text-align:center;color:var(--text-dim);padding:2rem;">Loading scan reports...</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  </div>

  <script>
    let activeTaskId = null;
    let pollInterval = null;

    document.getElementById('server-host').innerText = window.location.host;

    async function loadScans() {
      try {
        const res = await fetch('/api/scans');
        const data = await res.json();
        const tbody = document.getElementById('scans-tbody');
        if (!data.scans || data.scans.length === 0) {
          tbody.innerHTML = '<tr><td colspan="4" style="text-align:center;color:var(--text-dim);padding:2rem;">No previous scans recorded yet.</td></tr>';
          return;
        }
        tbody.innerHTML = data.scans.map(s => `
          <tr>
            <td style="font-family:var(--mono-font); font-weight:700; color:var(--text-main);">
              ${s.target}
            </td>
            <td>
              <span class="badge ${s.mode === 'domain' ? 'badge-domain' : 'badge-user'}">${s.mode}</span>
            </td>
            <td style="color:var(--text-dim); font-size:0.8rem;">
              ${s.date}
            </td>
            <td>
              <div style="display:flex; gap:0.5rem; flex-wrap:wrap;">
                <a class="link-btn" href="/reports/${encodeURIComponent(s.dir)}/report.html" target="_blank">🌐 HTML Web View</a>
                <a class="link-btn" style="color:var(--accent-blue); background:rgba(56,189,248,0.12);" href="/reports/${encodeURIComponent(s.dir)}/findings.json" target="_blank">JSON</a>
                <a class="link-btn" style="color:#f59e0b; background:rgba(245,158,11,0.12);" href="/reports/${encodeURIComponent(s.dir)}/REPORT.md" target="_blank">Markdown</a>
              </div>
            </td>
          </tr>
        `).join('');
      } catch (err) {
        console.error(err);
      }
    }

    document.getElementById('scan-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const btn = document.getElementById('submit-btn');
      const consoleOut = document.getElementById('console-output');
      btn.disabled = true;
      btn.innerText = '⏳ Scan Running...';
      consoleOut.innerText = '[~] Initializing ReconX scan...\n';

      const formData = new FormData(e.target);
      const payload = {
        mode: formData.get('mode'),
        target: formData.get('target'),
        threads: formData.get('threads') || 8,
        active: formData.get('active') !== null,
        takeovers: formData.get('takeovers') !== null,
        buckets: formData.get('buckets') !== null,
        security_headers: formData.get('security-headers') !== null,
        vhosts: formData.get('vhosts') !== null,
        ptr_sweep: formData.get('ptr-sweep') !== null,
      };

      try {
        const res = await fetch('/api/scan', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });
        const data = await res.json();
        if (data.task_id) {
          activeTaskId = data.task_id;
          pollTask(activeTaskId);
        } else {
          consoleOut.innerText += `[!] Error: ${data.error || 'Failed to start scan'}\n`;
          btn.disabled = false;
          btn.innerText = '⚡ Start Scan';
        }
      } catch (err) {
        consoleOut.innerText += `[!] Network error: ${err.message}\n`;
        btn.disabled = false;
        btn.innerText = '⚡ Start Scan';
      }
    });

    function pollTask(taskId) {
      if (pollInterval) clearInterval(pollInterval);
      pollInterval = setInterval(async () => {
        try {
          const res = await fetch(`/api/scan/${taskId}`);
          const data = await res.json();
          const consoleOut = document.getElementById('console-output');
          consoleOut.innerText = data.logs || 'Executing workers...';
          consoleOut.scrollTop = consoleOut.scrollHeight;

          if (data.status === 'completed' || data.status === 'failed') {
            clearInterval(pollInterval);
            const btn = document.getElementById('submit-btn');
            btn.disabled = false;
            btn.innerText = '⚡ Start Scan';
            loadScans();
          }
        } catch (err) {
          console.error(err);
        }
      }, 1500);
    }

    loadScans();
  </script>
</body>
</html>
"""

class ReconXWebHandler(SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        # Silence default HTTP access logs to keep CLI output clean
        pass

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path in ("/", "/index.html"):
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(HTML_DASHBOARD.encode("utf-8"))
            return

        elif path == "/api/scans":
            self._handle_api_scans()
            return

        elif path.startswith("/api/scan/"):
            task_id = path.replace("/api/scan/", "").strip()
            self._handle_api_task(task_id)
            return

        elif path.startswith("/reports/"):
            self._handle_serve_report(path.replace("/reports/", "", 1))
            return

        self.send_error(HTTPStatus.NOT_FOUND, "Not Found")

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/scan":
            self._handle_api_start_scan()
            return
        self.send_error(HTTPStatus.NOT_FOUND, "Not Found")

    def _handle_api_scans(self):
        scans = []
        if os.path.exists(OUTPUT_BASE):
            for entry in sorted(os.listdir(OUTPUT_BASE), reverse=True):
                if entry.startswith("."):
                    continue
                full_p = os.path.join(OUTPUT_BASE, entry)
                if os.path.isdir(full_p):
                    # parse dir naming: {mode}_{target}_{date}_{time}
                    parts = entry.split("_")
                    mode = parts[0] if parts else "unknown"
                    date_str = " ".join(parts[-2:]) if len(parts) >= 3 else entry
                    target_name = "_".join(parts[1:-2]) if len(parts) > 3 else entry
                    scans.append({
                        "dir": entry,
                        "mode": mode,
                        "target": target_name or entry,
                        "date": date_str,
                    })

        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"scans": scans}).encode("utf-8"))

    def _handle_api_task(self, task_id: str):
        task = ACTIVE_TASKS.get(task_id)
        if not task:
            self.send_response(HTTPStatus.NOT_FOUND)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": "Task not found"}).encode("utf-8"))
            return

        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({
            "status": task.get("status"),
            "logs": "".join(task.get("logs", [])),
        }).encode("utf-8"))

    def _handle_api_start_scan(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8")
            data = json.loads(body)
        except Exception:
            self.send_error(HTTPStatus.BAD_REQUEST, "Invalid JSON")
            return

        target = data.get("target", "").strip()
        mode = data.get("mode", "domain").strip()
        if not target:
            self.send_response(HTTPStatus.BAD_REQUEST)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": "Missing target parameter"}).encode("utf-8"))
            return

        task_id = f"task_{int(time.time() * 1000)}"
        ACTIVE_TASKS[task_id] = {
            "status": "running",
            "logs": [f"[*] Starting {mode} recon against {target}...\n"],
            "target": target,
        }

        # Build reconx command line
        cmd = [sys.executable, "-m", "reconx.cli", mode, target]
        if mode == "domain":
            if data.get("active"):
                cmd.append("--active")
            if data.get("takeovers"):
                cmd.append("--takeovers")
            if data.get("buckets"):
                cmd.append("--buckets")
            if data.get("security_headers"):
                cmd.append("--security-headers")
            if data.get("vhosts"):
                cmd.append("--vhosts")
            if data.get("ptr_sweep"):
                cmd.append("--ptr-sweep")
        threads = str(data.get("threads", 8))
        cmd.extend(["-t", threads])

        # Spawn background execution thread
        def _run_worker():
            try:
                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                )
                if proc.stdout:
                    for line in proc.stdout:
                        ACTIVE_TASKS[task_id]["logs"].append(line)
                proc.wait()
                ACTIVE_TASKS[task_id]["status"] = "completed" if proc.returncode == 0 else "failed"
            except Exception as e:
                ACTIVE_TASKS[task_id]["logs"].append(f"\n[!] Execution exception: {e}\n")
                ACTIVE_TASKS[task_id]["status"] = "failed"

        threading.Thread(target=_run_worker, daemon=True).start()

        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"task_id": task_id, "status": "running"}).encode("utf-8"))

    def _handle_serve_report(self, rel_path: str):
        # Sanitize rel_path
        safe_path = os.path.normpath(rel_path).lstrip("/\\")
        full_path = os.path.join(OUTPUT_BASE, safe_path)

        # Path traversal guard
        if not full_path.startswith(OUTPUT_BASE):
            self.send_error(HTTPStatus.FORBIDDEN, "Forbidden")
            return

        if not os.path.exists(full_path) or os.path.isdir(full_path):
            self.send_error(HTTPStatus.NOT_FOUND, "Report artifact not found")
            return

        mime_type, _ = mimetypes.guess_type(full_path)
        mime_type = mime_type or "application/octet-stream"
        if full_path.endswith(".md"):
            mime_type = "text/markdown; charset=utf-8"

        try:
            with open(full_path, "rb") as f:
                content = f.read()
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", mime_type)
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
        except Exception:
            self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR, "Error reading file")

def run_web_server(host: str = "127.0.0.1", port: int = 8080) -> None:
    """Start the ReconX Web GUI server."""
    os.makedirs(OUTPUT_BASE, exist_ok=True)
    server_address = (host, port)
    httpd = ThreadingHTTPServer(server_address, ReconXWebHandler)
    url = f"http://{host}:{port}"
    print("\n" + "=" * 76)
    print("  🌐 ReconX Interactive Web GUI & Management Server")
    print("=" * 76)
    print(f"  • Dashboard URL    : {url}")
    print(f"  • Local Web Access : Click or open in browser: {url}")
    print(f"  • Output Directory : {OUTPUT_BASE}")
    print(f"  • Press Ctrl+C in terminal to stop server.")
    print("=" * 76 + "\n")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down ReconX Web GUI server...")
        httpd.server_close()
