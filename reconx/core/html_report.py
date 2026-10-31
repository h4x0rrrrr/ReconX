"""Self-contained interactive HTML reporting dashboard with modern dark cyber theme."""
from __future__ import annotations

import html
import json
from datetime import datetime
from typing import Any

def _escape(val: Any) -> str:
    if val is None:
        return ""
    if isinstance(val, (list, dict)):
        return html.escape(json.dumps(val))
    return html.escape(str(val))

def generate_html_report(report_data: dict[str, Any]) -> str:
    target = _escape(report_data.get("target", "Target"))
    mode = _escape(report_data.get("mode", "recon"))
    gen_at = _escape(report_data.get("generated_at", ""))
    flags = report_data.get("flags", [])
    data = report_data.get("data", {})

    # Compute key stats
    subdomains = data.get("subdomains", [])
    network_services = data.get("network_services", [])
    live_cert = data.get("live_certificate")
    all_certs = data.get("certificates", [])
    live_hosts = data.get("live_hosts", [])
    hist_urls = data.get("historical_urls", [])
    buckets = data.get("cloud_buckets", [])
    takeovers = data.get("takeovers", [])
    gateways = data.get("perimeter_gateways", [])
    sec_headers = data.get("security_headers", [])
    dns_records = data.get("dns_records", {})
    m365 = data.get("m365_identity", {})
    email_sec = data.get("email_security", {})
    source_status = data.get("source_status", [])
    vulns = data.get("vulnerabilities", [])
    origin_ips = data.get("origin_ips", [])
    asn_ranges = data.get("asn_ranges", [])
    ntlm_items = data.get("ntlm_disclosure", [])
    github_intel = data.get("github_intel", {})

    high_flags = [f for f in flags if f.get("severity") == "high"]
    med_flags = [f for f in flags if f.get("severity") == "medium"]
    low_flags = [f for f in flags if f.get("severity") == "low"]
    info_flags = [f for f in flags if f.get("severity") == "info"]

    cert_status_badge = ""
    if live_cert:
        st = live_cert.get("status", "valid")
        if st == "expired":
            cert_status_badge = '<span class="badge badge-high">EXPIRED</span>'
        elif st == "expiring_soon":
            cert_status_badge = f'<span class="badge badge-med">EXPIRING IN {live_cert.get("days_remaining", 0)}d</span>'
        else:
            cert_status_badge = f'<span class="badge badge-ok">VALID ({live_cert.get("days_remaining", 0)}d remaining)</span>'

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ReconX Threat Intelligence Dashboard — {target}</title>
<style>
:root {{
  --bg: #0b0f19;
  --card: #111827;
  --card-border: #1f2937;
  --text: #f3f4f6;
  --text-muted: #9ca3af;
  --cyan: #06b6d4;
  --green: #10b981;
  --yellow: #f59e0b;
  --red: #ef4444;
  --blue: #3b82f6;
  --purple: #8b5cf6;
}}
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{
  background: var(--bg);
  color: var(--text);
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
  line-height: 1.5;
  padding: 24px;
}}
.container {{ max-width: 1400px; margin: 0 auto; }}
header {{
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding-bottom: 24px;
  border-bottom: 1px solid var(--card-border);
  margin-bottom: 24px;
  flex-wrap: wrap;
  gap: 16px;
}}
.brand {{ display: flex; align-items: center; gap: 12px; }}
.brand-logo {{
  background: linear-gradient(135deg, var(--cyan), var(--blue));
  color: #fff;
  font-weight: 900;
  font-size: 1.25rem;
  padding: 8px 14px;
  border-radius: 8px;
  letter-spacing: 1px;
}}
.brand-title h1 {{ font-size: 1.5rem; font-weight: 700; color: #fff; }}
.brand-title p {{ font-size: 0.85rem; color: var(--text-muted); }}
.header-actions {{ display: flex; gap: 10px; }}
.btn {{
  background: var(--card);
  color: var(--text);
  border: 1px solid var(--card-border);
  padding: 8px 14px;
  border-radius: 6px;
  font-size: 0.85rem;
  cursor: pointer;
  text-decoration: none;
  transition: all 0.2s;
}}
.btn:hover {{ border-color: var(--cyan); color: var(--cyan); }}
.btn-primary {{ background: var(--cyan); color: #000; border-color: var(--cyan); font-weight: 600; }}
.btn-primary:hover {{ background: #0891b2; color: #fff; }}

/* KPI Cards */
.kpi-grid {{
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(190px, 1fr));
  gap: 16px;
  margin-bottom: 24px;
}}
.kpi-card {{
  background: var(--card);
  border: 1px solid var(--card-border);
  border-radius: 10px;
  padding: 16px;
  display: flex;
  flex-direction: column;
  transition: transform 0.2s;
}}
.kpi-card:hover {{ transform: translateY(-2px); border-color: #374151; }}
.kpi-title {{ font-size: 0.75rem; text-transform: uppercase; color: var(--text-muted); letter-spacing: 0.5px; font-weight: 600; }}
.kpi-value {{ font-size: 1.75rem; font-weight: 800; color: #fff; margin-top: 6px; }}
.kpi-cyan {{ border-left: 4px solid var(--cyan); }}
.kpi-green {{ border-left: 4px solid var(--green); }}
.kpi-yellow {{ border-left: 4px solid var(--yellow); }}
.kpi-red {{ border-left: 4px solid var(--red); }}
.kpi-purple {{ border-left: 4px solid var(--purple); }}
.kpi-blue {{ border-left: 4px solid var(--blue); }}

/* Alerts */
.alerts-card {{
  background: var(--card);
  border: 1px solid var(--card-border);
  border-radius: 10px;
  padding: 20px;
  margin-bottom: 24px;
}}
.alerts-title {{ font-size: 1.1rem; font-weight: 700; margin-bottom: 14px; display: flex; align-items: center; justify-content: space-between; }}
.flags-list {{ list-style: none; display: flex; flex-direction: column; gap: 8px; }}
.flag-item {{
  display: flex;
  align-items: flex-start;
  gap: 10px;
  padding: 10px 14px;
  border-radius: 6px;
  font-size: 0.88rem;
}}
.flag-high {{ background: rgba(239, 68, 68, 0.12); border: 1px solid rgba(239, 68, 68, 0.3); color: #fca5a5; }}
.flag-medium {{ background: rgba(245, 158, 11, 0.12); border: 1px solid rgba(245, 158, 11, 0.3); color: #fde68a; }}
.flag-low {{ background: rgba(59, 130, 246, 0.12); border: 1px solid rgba(59, 130, 246, 0.3); color: #bfdbfe; }}
.flag-info {{ background: rgba(6, 182, 212, 0.12); border: 1px solid rgba(6, 182, 212, 0.3); color: #a5f3fc; }}
.badge {{
  font-size: 0.7rem;
  font-weight: 700;
  padding: 2px 8px;
  border-radius: 4px;
  text-transform: uppercase;
  white-space: nowrap;
}}
.badge-high {{ background: var(--red); color: #fff; }}
.badge-med {{ background: var(--yellow); color: #000; }}
.badge-low {{ background: var(--blue); color: #fff; }}
.badge-info {{ background: var(--cyan); color: #000; }}
.badge-ok {{ background: var(--green); color: #000; }}
.badge-tech {{ background: rgba(59, 130, 246, 0.2); color: #93c5fd; border: 1px solid rgba(59, 130, 246, 0.35); font-size: 0.72rem; padding: 2px 6px; border-radius: 4px; display: inline-block; margin: 1px; }}

/* Tabs */
.tabs-nav {{
  display: flex;
  gap: 8px;
  border-bottom: 1px solid var(--card-border);
  margin-bottom: 20px;
  overflow-x: auto;
  padding-bottom: 4px;
}}
.tab-btn {{
  background: none;
  border: none;
  color: var(--text-muted);
  font-size: 0.9rem;
  font-weight: 600;
  padding: 10px 16px;
  border-radius: 6px;
  cursor: pointer;
  white-space: nowrap;
  transition: all 0.2s;
}}
.tab-btn:hover {{ color: #fff; background: rgba(255, 255, 255, 0.04); }}
.tab-btn.active {{ color: var(--cyan); border-bottom: 2px solid var(--cyan); border-radius: 6px 6px 0 0; background: rgba(6, 182, 212, 0.08); }}

/* Search bar */
.search-box {{
  width: 100%;
  max-width: 360px;
  background: #1e293b;
  border: 1px solid var(--card-border);
  color: #fff;
  padding: 8px 14px;
  border-radius: 6px;
  font-size: 0.85rem;
  margin-bottom: 16px;
}}
.search-box:focus {{ outline: none; border-color: var(--cyan); }}

/* Tab Content */
.tab-pane {{ display: none; }}
.tab-pane.active {{ display: block; }}

/* Tables */
.table-wrap {{
  overflow-x: auto;
  border: 1px solid var(--card-border);
  border-radius: 8px;
  margin-bottom: 20px;
}}
table {{
  width: 100%;
  border-collapse: collapse;
  text-align: left;
  font-size: 0.85rem;
}}
th {{
  background: #172033;
  color: var(--text-muted);
  font-weight: 600;
  padding: 12px 16px;
  border-bottom: 1px solid var(--card-border);
  text-transform: uppercase;
  font-size: 0.72rem;
  letter-spacing: 0.5px;
}}
td {{
  padding: 10px 16px;
  border-bottom: 1px solid var(--card-border);
  color: #e5e7eb;
}}
tr:hover td {{ background: rgba(255, 255, 255, 0.02); }}

/* Cert Card */
.cert-hero {{
  background: linear-gradient(180deg, #162032, #111827);
  border: 1px solid #253347;
  border-radius: 10px;
  padding: 24px;
  margin-bottom: 24px;
}}
.cert-hero h3 {{ font-size: 1.25rem; font-weight: 700; margin-bottom: 6px; display: flex; align-items: center; gap: 12px; }}
.cert-grid {{
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
  gap: 16px;
  margin-top: 16px;
}}
.cert-field {{ font-size: 0.85rem; }}
.cert-field label {{ color: var(--text-muted); font-size: 0.75rem; text-transform: uppercase; font-weight: 600; display: block; margin-bottom: 4px; }}
.cert-field span {{ color: #fff; font-family: monospace; }}
.sans-chips {{ display: flex; flex-wrap: wrap; gap: 6px; margin-top: 10px; }}
.san-chip {{ background: #1e293b; border: 1px solid #334155; color: var(--cyan); padding: 3px 8px; border-radius: 4px; font-size: 0.75rem; font-family: monospace; }}

/* Code pill */
code {{
  background: #1e293b;
  color: #e2e8f0;
  padding: 2px 6px;
  border-radius: 4px;
  font-family: monospace;
  font-size: 0.82rem;
}}
footer {{
  margin-top: 40px;
  padding-top: 20px;
  border-top: 1px solid var(--card-border);
  color: var(--text-muted);
  font-size: 0.8rem;
  text-align: center;
}}
</style>
</head>
<body>
<div class="container">

  <!-- Header -->
  <header>
    <div class="brand">
      <div class="brand-logo">RECONX</div>
      <div class="brand-title">
        <h1>{target}</h1>
        <p>Mode: <code>{mode}</code> · Generated: <code>{gen_at}</code> · ReconX v0.3.3</p>
      </div>
    </div>
    <div class="header-actions">
      <button class="btn" onclick="window.print()">Print / PDF</button>
      <a class="btn btn-primary" href="findings.json" target="_blank">View JSON Model</a>
    </div>
  </header>

  <!-- KPI Stats -->
  <div class="kpi-grid">
    <div class="kpi-card kpi-cyan">
      <span class="kpi-title">Subdomains</span>
      <span class="kpi-value">{len(subdomains)}</span>
    </div>
    <div class="kpi-card kpi-purple">
      <span class="kpi-title">Open Services (Ports)</span>
      <span class="kpi-value">{len(network_services)}</span>
    </div>
    <div class="kpi-card kpi-green">
      <span class="kpi-title">Certificates</span>
      <span class="kpi-value">{len(all_certs)}</span>
    </div>
    <div class="kpi-card kpi-red">
      <span class="kpi-title">Security Flags</span>
      <span class="kpi-value">{len(flags)}</span>
    </div>
    <div class="kpi-card kpi-blue">
      <span class="kpi-title">Live Hosts</span>
      <span class="kpi-value">{len(live_hosts)}</span>
    </div>
    <div class="kpi-card kpi-yellow">
      <span class="kpi-title">Historical URLs</span>
      <span class="kpi-value">{len(hist_urls)}</span>
    </div>
  </div>

  <!-- Security Findings / Alerts -->
  <div class="alerts-card">
    <div class="alerts-title">
      <span>Automated Findings & Risk Assessment ({len(flags)})</span>
      <div>
        <span class="badge badge-high">{len(high_flags)} High</span>
        <span class="badge badge-med">{len(med_flags)} Medium</span>
        <span class="badge badge-low">{len(low_flags)} Low</span>
        <span class="badge badge-info">{len(info_flags)} Info</span>
      </div>
    </div>
    <ul class="flags-list">
"""

    if flags:
        for f in flags:
            sev = f.get("severity", "info").lower()
            note = _escape(f.get("note", ""))
            badge_cls = f"badge-{sev}" if sev in ("high", "low", "info") else "badge-med"
            html_content += f"""      <li class="flag-item flag-{sev}">
        <span class="badge {badge_cls}">{sev.upper()}</span>
        <span>{note}</span>
      </li>\n"""
    else:
        html_content += """      <li class="flag-item flag-info">
        <span class="badge badge-ok">PASS</span>
        <span>No automated risk flags detected on the audited perimeter.</span>
      </li>\n"""

    html_content += f"""    </ul>
  </div>

  <!-- Navigation Tabs -->
  <div class="tabs-nav">
    <button class="tab-btn active" onclick="switchTab('certs')">📜 Certificates ({len(all_certs)})</button>
    <button class="tab-btn" onclick="switchTab('services')">🌐 Open Ports & Services ({len(network_services)})</button>
    <button class="tab-btn" onclick="switchTab('vulns')">🎯 CVEs & Origins ({len(vulns) + len(origin_ips)})</button>
    <button class="tab-btn" onclick="switchTab('subs')">🔗 Subdomains ({len(subdomains)})</button>
    <button class="tab-btn" onclick="switchTab('dns')">📋 DNS Records</button>
    <button class="tab-btn" onclick="switchTab('infra')">📡 BGP & GitHub ({len(asn_ranges)})</button>
    <button class="tab-btn" onclick="switchTab('identity')">🏢 Cloud Identity & Email</button>
    <button class="tab-btn" onclick="switchTab('cloud')">☁️ Cloud Buckets & Takeovers</button>
    <button class="tab-btn" onclick="switchTab('gateways')">🚪 Gateways & Vhosts</button>
    <button class="tab-btn" onclick="switchTab('headers')">🛡️ Security Headers</button>
    <button class="tab-btn" onclick="switchTab('status')">📊 Pipeline Status</button>
  </div>

  <input type="text" class="search-box" id="tableSearch" placeholder="Quick search in current tab..." onkeyup="filterTable()">

  <!-- Tab 1: Certificates -->
  <div id="tab-certs" class="tab-pane active">
"""

    if live_cert:
        html_content += f"""
    <div class="cert-hero">
      <h3>Live TLS Certificate {cert_status_badge}</h3>
      <div class="cert-grid">
        <div class="cert-field"><label>Subject Common Name</label><span>{_escape(live_cert.get("common_name"))}</span></div>
        <div class="cert-field"><label>Issuer</label><span>{_escape(live_cert.get("issuer"))}</span></div>
        <div class="cert-field"><label>Validity Period</label><span>{_escape(live_cert.get("valid_from", "")[:10])} &rarr; {_escape(live_cert.get("valid_to", "")[:10])}</span></div>
        <div class="cert-field"><label>Serial Number</label><span>{_escape(live_cert.get("serial_number"))}</span></div>
        <div class="cert-field"><label>SHA-256 Fingerprint</label><span>{_escape(live_cert.get("sha256_fingerprint"))}</span></div>
        <div class="cert-field"><label>Verification Evidence</label><span>{_escape(live_cert.get("evidence"))}</span></div>
      </div>
      <div style="margin-top: 14px;">
        <label style="color: var(--text-muted); font-size: 0.75rem; text-transform: uppercase; font-weight: 600;">Subject Alternative Names ({len(live_cert.get("sans", []))})</label>
        <div class="sans-chips">
"""
        for san in live_cert.get("sans", []):
            html_content += f'          <span class="san-chip">{_escape(san)}</span>\n'
        html_content += """        </div>
      </div>
    </div>
"""

    html_content += f"""
    <h4 style="margin-bottom: 12px; font-weight: 700;">Certificate Transparency Log Records ({len(all_certs)})</h4>
    <div class="table-wrap">
      <table class="filterable">
        <thead>
          <tr>
            <th>Common Name</th>
            <th>Issuer</th>
            <th>Valid From</th>
            <th>Valid To</th>
            <th>Identities (SANs)</th>
            <th>Source</th>
          </tr>
        </thead>
        <tbody>
"""
    for c in all_certs:
        sans_str = ", ".join(c.get("sans", [])[:5])
        if len(c.get("sans", [])) > 5:
            sans_str += f" (+{len(c.get('sans', [])) - 5} more)"
        html_content += f"""          <tr>
            <td><strong>{_escape(c.get("common_name"))}</strong></td>
            <td>{_escape(c.get("issuer"))}</td>
            <td><code>{_escape(c.get("valid_from", "")[:10])}</code></td>
            <td><code>{_escape(c.get("valid_to", "")[:10])}</code></td>
            <td>{_escape(sans_str)}</td>
            <td><span class="badge badge-info">{_escape(c.get("source"))}</span></td>
          </tr>\n"""

    html_content += """        </tbody>
      </table>
    </div>
  </div>


  <!-- Tab 2: Open Ports & Network Services -->
  <div id="tab-services" class="tab-pane">
    <div class="table-wrap">
      <table class="filterable">
        <thead>
          <tr>
            <th>IP Address</th>
            <th>Port</th>
            <th>Service</th>
            <th>Product / OS</th>
            <th>Technologies</th>
            <th>Organization</th>
            <th>Source</th>
            <th>Intelligence Evidence</th>
          </tr>
        </thead>
        <tbody>
"""
    if network_services:
        for s in network_services:
            techs = s.get("technologies", [])
            tech_html = " ".join(f'<span class="badge badge-tech">{_escape(t)}</span>' for t in techs) if techs else '<span style="color:var(--text-muted);font-size:0.8rem;">—</span>'
            html_content += f"""          <tr>
            <td><code>{_escape(s.get("ip"))}</code></td>
            <td><span class="badge badge-med">{_escape(s.get("port"))}</span></td>
            <td><strong>{_escape(s.get("service") or s.get("product") or "unknown")}</strong></td>
            <td>{_escape(s.get("product", ""))}</td>
            <td>{tech_html}</td>
            <td>{_escape(s.get("org") or s.get("location") or "")}</td>
            <td><span class="badge badge-info">{_escape(s.get("source"))}</span></td>
            <td>{_escape(s.get("evidence", ""))}</td>
          </tr>\n"""
    else:
        html_content += '          <tr><td colspan="8" style="text-align: center; color: var(--text-muted);">No open network ports discovered via Shodan / Censys.</td></tr>\n'

    html_content += """        </tbody>
      </table>
    </div>
  </div>


  <!-- Tab 3: Subdomains -->
  <div id="tab-subs" class="tab-pane">
    <div class="table-wrap">
      <table class="filterable">
        <thead>
          <tr>
            <th>Subdomain Host</th>
            <th>Sources</th>
            <th>Evidence</th>
          </tr>
        </thead>
        <tbody>
"""
    for sub in subdomains:
        sources_str = ", ".join(sub.get("sources", [sub.get("source", "")]))
        html_content += f"""          <tr>
            <td><strong>{_escape(sub.get("host"))}</strong></td>
            <td><span class="badge badge-info">{_escape(sources_str)}</span></td>
            <td>{_escape(sub.get("evidence", ""))}</td>
          </tr>\n"""

    html_content += """        </tbody>
      </table>
    </div>
  </div>


  <!-- Tab 4: DNS Records -->
  <div id="tab-dns" class="tab-pane">
    <div class="table-wrap">
      <table class="filterable">
        <thead>
          <tr>
            <th>Record Type</th>
            <th>Value</th>
            <th>Source</th>
          </tr>
        </thead>
        <tbody>
"""
    for rtype, items in sorted(dns_records.items()):
        for it in items:
            val = it.get("value", "") if isinstance(it, dict) else str(it)
            src = it.get("source", "dns") if isinstance(it, dict) else "dns"
            html_content += f"""          <tr>
            <td><span class="badge badge-low">{_escape(rtype)}</span></td>
            <td><code>{_escape(val)}</code></td>
            <td>{_escape(src)}</td>
          </tr>\n"""

    html_content += """        </tbody>
      </table>
    </div>
  </div>


  <!-- Tab 5: Cloud Identity & Email -->
  <div id="tab-identity" class="tab-pane">
    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(360px, 1fr)); gap: 20px;">
      <div class="cert-hero">
        <h3>Microsoft 365 / Entra ID Architecture</h3>
        <div style="margin-top: 14px; display: flex; flex-direction: column; gap: 10px;">
          <div><label style="color: var(--text-muted); font-size: 0.75rem; text-transform: uppercase;">M365 Status</label> <strong>{'Active Organization' if m365.get('is_m365') else 'Not Detected'}</strong></div>
          <div><label style="color: var(--text-muted); font-size: 0.75rem; text-transform: uppercase;">Azure Tenant ID</label> <code>{_escape(m365.get('tenant_id') or 'Undisclosed')}</code></div>
          <div><label style="color: var(--text-muted); font-size: 0.75rem; text-transform: uppercase;">Namespace Type</label> {_escape(m365.get('namespace_type', 'Unknown'))}</div>
          <div><label style="color: var(--text-muted); font-size: 0.75rem; text-transform: uppercase;">Identity Architecture</label> {'Hybrid ADFS Federation' if m365.get('is_federated') else 'Pure Managed Azure AD'}</div>
        </div>
      </div>
      <div class="cert-hero">
        <h3>Email Security Gateway & DMARC Defense</h3>
        <div style="margin-top: 14px; display: flex; flex-direction: column; gap: 10px;">
          <div><label style="color: var(--text-muted); font-size: 0.75rem; text-transform: uppercase;">SEG Vendor</label> <strong>{_escape(email_sec.get('seg_vendor', 'Standard / Self-Hosted'))}</strong></div>
          <div><label style="color: var(--text-muted); font-size: 0.75rem; text-transform: uppercase;">DMARC Policy</label> <code>{_escape((email_sec.get('dmarc') or {}).get('policy', 'missing'))}</code> ({_escape((email_sec.get('dmarc') or {}).get('compliance', 'N/A'))})</div>
          <div><label style="color: var(--text-muted); font-size: 0.75rem; text-transform: uppercase;">Spoofing Risk</label> <span class="badge {('badge-high' if (email_sec.get('dmarc') or {}).get('spoofing_risk') == 'high' else 'badge-ok')}">{_escape((email_sec.get('dmarc') or {}).get('spoofing_risk', 'Unknown')).upper()}</span></div>
          <div><label style="color: var(--text-muted); font-size: 0.75rem; text-transform: uppercase;">SPF Record</label> <code>{_escape((email_sec.get('spf') or {}).get('record', 'None'))}</code></div>
        </div>
      </div>
    </div>
  </div>

  <!-- Tab 6: Cloud Buckets & Takeovers -->
  <div id="tab-cloud" class="tab-pane">
    <h4 style="margin-bottom: 12px; font-weight: 700;">Discovered Cloud Storage Buckets ({len(buckets)})</h4>
    <div class="table-wrap">
      <table class="filterable">
        <thead><tr><th>Bucket Name</th><th>Provider</th><th>Access Posture</th><th>URL</th></tr></thead>
        <tbody>
"""
    if buckets:
        for b in buckets:
            acc = b.get("access", "Unknown")
            bcls = "badge-high" if "Public" in acc else "badge-low"
            html_content += f"""          <tr>
            <td><strong>{_escape(b.get("name"))}</strong></td>
            <td>{_escape(b.get("provider"))}</td>
            <td><span class="badge {bcls}">{_escape(acc)}</span></td>
            <td><a href="{_escape(b.get("url"))}" target="_blank" style="color: var(--cyan);">{_escape(b.get("url"))}</a></td>
          </tr>\n"""
    else:
        html_content += '          <tr><td colspan="4" style="text-align: center; color: var(--text-muted);">No exposed cloud storage buckets detected.</td></tr>\n'

    html_content += f"""        </tbody>
      </table>
    </div>

    <h4 style="margin-bottom: 12px; font-weight: 700;">Subdomain Takeover Risks ({len(takeovers)})</h4>
    <div class="table-wrap">
      <table class="filterable">
        <thead><tr><th>Subdomain</th><th>CNAME Pointer</th><th>Claim Provider</th><th>Status</th><th>Evidence</th></tr></thead>
        <tbody>
"""
    if takeovers:
        for t in takeovers:
            html_content += f"""          <tr>
            <td><strong>{_escape(t.get("subdomain"))}</strong></td>
            <td><code>{_escape(t.get("cname"))}</code></td>
            <td>{_escape(t.get("provider"))}</td>
            <td><span class="badge badge-high">{_escape(t.get("status"))}</span></td>
            <td>{_escape(t.get("evidence"))}</td>
          </tr>\n"""
    else:
        html_content += '          <tr><td colspan="5" style="text-align: center; color: var(--text-muted);">No dangling CNAME takeover candidates observed.</td></tr>\n'

    html_content += """        </tbody>
      </table>
    </div>
  </div>


  <!-- Tab 7: Gateways -->
  <div id="tab-gateways" class="tab-pane">
    <div class="table-wrap">
      <table class="filterable">
        <thead><tr><th>Host</th><th>Vendor</th><th>Product</th><th>Status</th><th>URL</th></tr></thead>
        <tbody>
"""
    if gateways:
        for g in gateways:
            html_content += f"""          <tr>
            <td><strong>{_escape(g.get("host"))}</strong></td>
            <td>{_escape(g.get("vendor"))}</td>
            <td><span class="badge badge-med">{_escape(g.get("product"))}</span></td>
            <td>HTTP {_escape(g.get("status"))}</td>
            <td><a href="{_escape(g.get("url"))}" target="_blank" style="color: var(--cyan);">{_escape(g.get("url"))}</a></td>
          </tr>\n"""
    else:
        html_content += '          <tr><td colspan="5" style="text-align: center; color: var(--text-muted);">No perimeter remote access portals fingerprinted.</td></tr>\n'

    html_content += """        </tbody>
      </table>
    </div>
  </div>


  <!-- Tab 8: Security Headers -->
  <div id="tab-headers" class="tab-pane">
    <div class="table-wrap">
      <table class="filterable">
        <thead><tr><th>Host</th><th>Grade</th><th>Score</th><th>Missing Defensive Headers</th></tr></thead>
        <tbody>
"""
    if sec_headers:
        for sh in sec_headers:
            gr = sh.get("grade", "F")
            gcls = "badge-ok" if gr in ("A+", "A") else ("badge-med" if gr in ("B", "C") else "badge-high")
            missing = ", ".join(sh.get("missing", [])) or "None (Fully Fortified)"
            html_content += f"""          <tr>
            <td><strong>{_escape(sh.get("host"))}</strong></td>
            <td><span class="badge {gcls}">{_escape(gr)}</span></td>
            <td>{_escape(sh.get("score"))}/100</td>
            <td><span style="color: #fca5a5;">{_escape(missing)}</span></td>
          </tr>\n"""
    else:
        html_content += '          <tr><td colspan="4" style="text-align: center; color: var(--text-muted);">No live HTTP hosts audited for security headers (use --security-headers or --active).</td></tr>\n'

    html_content += """        </tbody>
      </table>
    </div>
  </div>


  <!-- Tab 9: Pipeline Status -->
  <div id="tab-status" class="tab-pane">
    <div class="table-wrap">
      <table class="filterable">
        <thead><tr><th>Data Provider / Source</th><th>Execution Status</th><th>Message / Details</th><th>Items Returned</th></tr></thead>
        <tbody>
"""
    for st in source_status:
        st_val = st.get("status", "ok")
        scls = "badge-ok" if st_val == "ok" else ("badge-low" if st_val == "not_configured" else "badge-med")
        html_content += f"""          <tr>
            <td><strong>{_escape(st.get("source"))}</strong></td>
            <td><span class="badge {scls}">{_escape(st_val)}</span></td>
            <td>{_escape(st.get("message", ""))}</td>
            <td>{_escape(st.get("items_returned", 0))}</td>
          </tr>\n"""

    html_content += """        </tbody>
      </table>
    </div>
  </div>


  <!-- Tab: Correlated Vulnerabilities & Origin IPs -->
  <div id="tab-vulns" class="tab-pane">
    <h3 style="margin-bottom: 12px; font-size: 1.1rem; color: var(--red);">🎯 Correlated Vulnerabilities & CISA KEV Advisories</h3>
    <div class="table-wrap" style="margin-bottom: 24px;">
      <table class="filterable">
        <thead><tr><th>CVE Advisory</th><th>Severity / CVSS</th><th>Technology / Host</th><th>Vulnerability Details</th><th>Reference</th></tr></thead>
        <tbody>
"""
    if vulns:
        for v in vulns:
            sev = v.get("severity", "HIGH")
            scls = "badge-high" if sev in ("CRITICAL", "HIGH") else "badge-med"
            cisa_badge = ' <span class="badge badge-high" style="background:#dc2626;">CISA KEV</span>' if v.get("cisa_kev") else ""
            html_content += f"""          <tr>
            <td><strong>{_escape(v.get("cve"))}</strong>{cisa_badge}</td>
            <td><span class="badge {scls}">{_escape(sev)} ({_escape(v.get("cvss"))})</span></td>
            <td><code>{_escape(v.get("technology"))}</code><br><small style="color:var(--text-muted);">{_escape(v.get("host"))}:{_escape(v.get("port"))}</small></td>
            <td><strong>{_escape(v.get("title"))}</strong><br><small style="color:var(--text-muted);">{_escape(v.get("summary"))}</small></td>
            <td><a href="{_escape(v.get("advisory"))}" target="_blank" style="color:var(--cyan);text-decoration:none;">Advisory &rarr;</a></td>
          </tr>\n"""
    else:
        html_content += '          <tr><td colspan="5" style="text-align:center;color:var(--text-muted);padding:16px;">No known high-profile CVEs matched currently identified technology versions.</td></tr>\n'

    html_content += """        </tbody>
      </table>
    </div>

    <h3 style="margin-bottom: 12px; font-size: 1.1rem; color: var(--yellow);">🛡️ Unmasked Origin IPs (WAF / CDN Bypass Candidates)</h3>
    <div class="table-wrap" style="margin-bottom: 24px;">
      <table class="filterable">
        <thead><tr><th>Unmasked Origin IP</th><th>Fronted By CDN</th><th>Matched Hostname</th><th>Confidence</th><th>Correlation Evidence</th></tr></thead>
        <tbody>
"""
    if origin_ips:
        for o in origin_ips:
            conf = o.get("confidence", "Medium")
            ccls = "badge-high" if conf == "High" else "badge-med"
            html_content += f"""          <tr>
            <td><strong style="color:var(--cyan);">{_escape(o.get("ip"))}</strong></td>
            <td><span class="badge badge-low">{_escape(o.get("fronted_by_cdn"))}</span></td>
            <td><code>{_escape(o.get("matched_host"))}</code></td>
            <td><span class="badge {ccls}">{_escape(conf)}</span></td>
            <td>{_escape(o.get("evidence"))}</td>
          </tr>\n"""
    else:
        html_content += '          <tr><td colspan="5" style="text-align:center;color:var(--text-muted);padding:16px;">No direct backend origin IPs were unmasked bypassing the CDN.</td></tr>\n'

    html_content += """        </tbody>
      </table>
    </div>

    <h3 style="margin-bottom: 12px; font-size: 1.1rem; color: var(--purple);">🔑 Active Directory NTLM Challenge Disclosures</h3>
    <div class="table-wrap">
      <table class="filterable">
        <thead><tr><th>Endpoint URL</th><th>Internal AD Domain</th><th>Computer Name</th><th>Windows OS Build</th></tr></thead>
        <tbody>
"""
    if ntlm_items:
        for n in ntlm_items:
            html_content += f"""          <tr>
            <td><code>{_escape(n.get("url"))}</code></td>
            <td><strong style="color:var(--purple);">{_escape(n.get("dns_domain_name") or n.get("netbios_domain_name", "N/A"))}</strong></td>
            <td>{_escape(n.get("dns_computer_name") or n.get("netbios_computer_name", "N/A"))}</td>
            <td><span class="badge badge-low">{_escape(n.get("os_version", "Windows"))}</span></td>
          </tr>\n"""
    else:
        html_content += '          <tr><td colspan="4" style="text-align:center;color:var(--text-muted);padding:16px;">No NTLM challenge identity disclosures observed.</td></tr>\n'

    html_content += """        </tbody>
      </table>
    </div>
  </div>

  <!-- Tab: Infrastructure, ASN & GitHub -->
  <div id="tab-infra" class="tab-pane">
    <h3 style="margin-bottom: 12px; font-size: 1.1rem; color: var(--blue);">📡 Autonomous Systems (ASNs) & BGP Netblocks</h3>
    <div class="table-wrap" style="margin-bottom: 24px;">
      <table class="filterable">
        <thead><tr><th>Autonomous System (ASN)</th><th>BGP CIDR Prefix</th><th>Organization / Description</th><th>Country</th><th>Source</th></tr></thead>
        <tbody>
"""
    if asn_ranges:
        for a in asn_ranges:
            html_content += f"""          <tr>
            <td><strong style="color:var(--cyan);">{_escape(a.get("asn"))}</strong></td>
            <td><code>{_escape(a.get("cidr"))}</code></td>
            <td>{_escape(a.get("asn_name") or a.get("description", "Unknown"))}</td>
            <td><span class="badge badge-low">{_escape(a.get("country", ""))}</span></td>
            <td>{_escape(a.get("source", "BGP"))}</td>
          </tr>\n"""
    else:
        html_content += '          <tr><td colspan="5" style="text-align:center;color:var(--text-muted);padding:16px;">No Autonomous System (ASN) netblocks resolved.</td></tr>\n'

    html_content += """        </tbody>
      </table>
    </div>

    <h3 style="margin-bottom: 12px; font-size: 1.1rem; color: var(--green);">🐙 GitHub Organization Open-Source Intelligence</h3>
    <div class="table-wrap">
      <table class="filterable">
        <thead><tr><th>Repository Name</th><th>Primary Stack</th><th>Stars</th><th>Security Indicator</th><th>Description</th></tr></thead>
        <tbody>
"""
    if github_intel and github_intel.get("repositories"):
        for r in github_intel.get("repositories", []):
            sens_badge = '<span class="badge badge-med">INFRA / SEC</span>' if r.get("sensitive_indicator") else ""
            html_content += f"""          <tr>
            <td><a href="{_escape(r.get("url"))}" target="_blank" style="color:var(--cyan);font-weight:600;text-decoration:none;">{_escape(r.get("name"))}</a> {sens_badge}</td>
            <td><span class="badge badge-low">{_escape(r.get("language") or "N/A")}</span></td>
            <td>⭐ {_escape(r.get("stars", 0))}</td>
            <td>{_escape("Sensitive keyword match" if r.get("sensitive_indicator") else "Standard public repo")}</td>
            <td>{_escape(r.get("description") or "No description provided")}</td>
          </tr>\n"""
    else:
        html_content += '          <tr><td colspan="5" style="text-align:center;color:var(--text-muted);padding:16px;">No public GitHub organization repositories identified.</td></tr>\n'

    html_content += """        </tbody>
      </table>
    </div>
  </div>

  <footer>
    ReconX v0.3.3 &mdash; Red-Team Attack Surface & Open Source Intelligence Engine &mdash; Designed for authorized security research.
  </footer>
</div>

<script>
function switchTab(name) {
  document.querySelectorAll('.tab-pane').forEach(el => el.classList.remove('active'));
  document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
  const target = document.getElementById('tab-' + name);
  if (target) {
    target.classList.add('active');
  }
  event.currentTarget.classList.add('active');
  filterTable();
}

function filterTable() {
  const q = document.getElementById('tableSearch').value.toLowerCase();
  const activePane = document.querySelector('.tab-pane.active');
  if (!activePane) return;
  const rows = activePane.querySelectorAll('table.filterable tbody tr');
  rows.forEach(r => {
    const text = r.textContent.toLowerCase();
    r.style.display = text.includes(q) ? '' : 'none';
  });
}
</script>
</body>
</html>
"""
    return html_content
