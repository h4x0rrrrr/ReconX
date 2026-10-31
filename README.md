# ReconX 0.3.3

**A passive-first, plugin-based OSINT and red-team reconnaissance CLI** for authorized security engagements. ReconX focuses on high-fidelity findings, clear provenance, concurrent collection, conservative independent verification, OPSEC proxy routing, and unified multi-format reports—not noisy, unverified dumps.

---

## Design Principles

- **Verified-only username output:** Candidate profiles from Sherlock and WhatsMyName are treated as candidates, not ground truth. ReconX independently verifies HTTP status codes, redirects, not-found markers, and confirms the username is present in the rendered page content. Blocked, ambiguous, or unconfirmed candidates are omitted.
- **Breach & credential intelligence:** Query HaveIBeenPwned (HIBP) for exposed account breaches and pastes. API secrets and unredacted passwords are never printed or written to reports.
- **JavaScript & API endpoint discovery:** Identifies both passive API endpoints from historical archives and active endpoints parsed from inline `<script>` tags and external JS bundles.
- **Document metadata & username convention cracking:** Automatically harvests public PDFs, DOCX, and XLSX files to extract author/creator metadata via `exiftool` (or pure-Python fallback) and infer corporate username naming conventions (`first.last`, `flast`, `firstl`).
- **Live Certificate Transparency:** Continuous real-time monitoring via CertStream WebSocket (`reconx watch <domain>`) to detect newly registered subdomains and staging environments as certificates are issued.
- **Reverse DNS & PTR infrastructure sweep:** Bounded reverse DNS resolution on discovered IPs and subnets to map internal naming conventions (`vpn-gw`, `mail-relay`, `admin-portal`, `corp-dc`).
- **Microsoft 365 & Entra ID realm discovery:** Passively queries Microsoft's public OpenID and user realm endpoints to extract the target's unique Azure Tenant GUID, identify whether identity is Managed (cloud-native) or Federated (hybrid on-prem ADFS/STS), and extract the STS authentication URL.
- **Email Security Gateway (SEG) & DMARC defense audit:** Automatically classifies inbound mail exchangers (Proofpoint, Mimecast, Microsoft Defender for Office 365, Google Workspace, Barracuda, Cisco IronPort) and audits DMARC/SPF compliance to evaluate domain spoofing resistance.
- **Perimeter gateway & remote access fingerprinting:** Detects exposed enterprise VPN and remote access portals across discovered subdomains (Palo Alto GlobalProtect, Citrix NetScaler Gateway, Fortinet FortiGate, Cisco AnyConnect, Pulse Connect Secure, SonicWall) and records them in `gateways.csv`.
- **Vendor & supply-chain correlation:** Discovers shared tracking and analytics IDs (GA4, Universal Analytics, GTM, AdSense, Meta Pixel, Hotjar) to uncover undisclosed subsidiaries and vendor relationships.
- **OPSEC & proxy routing:** Route all HTTP/HTTPS and DNS traffic through SOCKS5 (Tor) or HTTP proxies (`--proxy socks5://127.0.0.1:9050` or `--proxy http://127.0.0.1:8080`) with exponential backoff on rate limits.
- **SQLite caching layer:** Built-in local request cache with TTL to eliminate redundant requests and respect rate limits. Can be bypassed on demand with `--no-cache`.
- **Multi-format reporting:** Unified Markdown (`REPORT.md`), structured JSON (`findings.json`), individual CSV tables (`subdomains.csv`, `dns_records.csv`, `gateways.csv`, `js_endpoints.csv`, `breaches.csv`, etc.), and category text files for pipeline chaining.

---

## Installation (Kali / Linux)

```bash
cd ReconX
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
reconx check
reconx --help

## Quick Usage Cheatsheet

```bash
# 1. Environment & readiness check
reconx check

# 2. Fast passive domain recon (CRT.sh, DNS, RDAP/WHOIS, Wayback CDX, BGPView, M365 Tenant & SEG/DMARC Audit)
reconx domain example.com

# 3. Full red-team attack surface sweep (Active HTTP, TLS SANs, Gateways/VPNs, JS endpoints, Vhosts, PTR sweep)
reconx domain example.com --deep --active --vhosts --ptr-sweep

# 4. Red-team cloud audit (Dangling CNAME takeovers, S3/Azure/GCP storage buckets, HTTP security headers)
reconx domain example.com --active --takeovers --buckets --security-headers

# 5. Route entire scan through Tor (OPSEC)
reconx domain example.com --active --proxy socks5://127.0.0.1:9050

# 6. Live Certificate Transparency monitoring (watch for new subdomains in real time)
reconx watch example.com

# 7. Username recon with WhatsMyName, Sherlock, and HaveIBeenPwned breach intel
reconx username targetuser

# 8. Targeted person OSINT with strict filters
reconx person "Jane Example" --location "London, UK" --organization "Target Labs" --keyword security

# 9. Launch the interactive local Web GUI Dashboard & REST API
reconx serve --port 8080

# 10. Filter specific output formats (default: txt + HTML web view; or choose csv, json, md, all)
reconx domain example.com --format csv,json
reconx domain example.com -f all

# 11. Send scan completion alerts to Discord or Slack
reconx domain example.com --webhook https://discord.com/api/webhooks/...
```

---

## Interactive Web GUI (`reconx serve`)

ReconX features a built-in dark-themed cyber dashboard:
```bash
reconx serve --port 8080
```
- **Web Dashboard**: Access at `http://127.0.0.1:8080` in any browser.
- **Interactive Scans**: Launch domain, username, or person scans directly from the UI.
- **Live Console Streaming**: Monitor background scan execution and worker status in real time.
- **Reports Hub**: One-click viewing of interactive HTML dashboards (`report.html`), Markdown executive reports, and direct CSV/JSON downloads.
- **REST API**: Integrates with `/api/scans`, `/api/scan`, and `/api/scan/<task_id>`.

---

## Usage & Commands Reference

### 1. Readiness & Tool Check
Inspect available Python dependencies, external binaries (`subfinder`, `amass`, `sherlock`, `exiftool`), proxy configuration, and API provider status:
```bash
reconx check
```

### 2. Domain Attack Surface Recon
```bash
# 1. Standard passive domain recon (CRT.sh, DNS, RDAP/WHOIS, Wayback CDX, BGPView, M365 Tenant, SEG/DMARC)
reconx domain example.com

# 2. Add passive Subfinder/Amass tools + active HTTP/TLS probes, JS endpoints, doc metadata & perimeter gateways
reconx domain example.com --deep --active

# 3. Add virtual host candidate discovery (Host-header fingerprint comparison)
reconx domain example.com --vhosts

# 4. Use a custom virtual host wordlist (up to 500 valid labels)
reconx domain example.com --vhosts --vhost-wordlist ./vhosts.txt

# 5. Perform reverse DNS (PTR) sweep on discovered IPs
reconx domain example.com --ptr-sweep

# 6. Audit subdomains for dangling CNAME pointers and cloud service takeover risks
reconx domain example.com --takeovers

# 7. Audit cloud storage bucket permutations (AWS S3, Azure Blob, Google Cloud Storage)
reconx domain example.com --buckets

# 8. Audit HTTP security headers & defensive posture (HSTS, CSP, XFO, etc.)
reconx domain example.com --active --security-headers

# 9. Bypass local SQLite request cache
reconx domain example.com --no-cache

# 10. Route entire recon scan through SOCKS5 Tor proxy (OPSEC)
reconx domain example.com --proxy socks5://127.0.0.1:9050

# 11. Route through an interception proxy (e.g., Burp Suite / ZAP)
reconx domain example.com --proxy http://127.0.0.1:8080

# 12. Complete full-spectrum red-team audit
reconx domain example.com --deep --active --vhosts --ptr-sweep --takeovers --buckets --security-headers
```

### 3. Real-Time Certificate Monitoring (CertStream)
Stream Certificate Transparency logs in real time to catch newly issued certificates and staging domains as they are stood up:
```bash
# Watch continuously until interrupted (Ctrl+C)
reconx watch example.com

# Watch for 5 minutes (300 seconds)
reconx watch example.com --timeout 300

# Stop after finding 5 matching certificates
reconx watch example.com --max-matches 5

# Route stream monitor through Tor
reconx watch example.com --proxy socks5://127.0.0.1:9050
```

### 4. Username Recon & Breach Intelligence
Combines Sherlock, WhatsMyName, and native sites with conservative independent verification and HaveIBeenPwned breach lookups:
```bash
# Standard username lookup
reconx username targetuser

# Route lookup through Tor proxy
reconx username targetuser --proxy socks5://127.0.0.1:9050

# Force live re-verification bypassing local cache
reconx username targetuser --no-cache
```

### 5. Filtered Person Search
Search public web results with strict name matching and required/excluded filters:
```bash
# Search with required location and organization
reconx person "Jane Example" --location "Patna, India" --organization "Example Labs"

# Include required keywords, exclude noise terms, limit results
reconx person "Jane Example" --location "Patna, India" \
  --keyword security --keyword engineering \
  --exclude obituary --max-results 15
```

---

## Output Files & Report Structure

Reports are saved in `recon_output/<mode>_<target>_<timestamp>/`:

| File | Format | Description |
|---|---|---|
| **`report.html`** | HTML5 | **Interactive single-page dashboard** with dark cyber theme, KPI cards, and tabbed tables |
| **`REPORT.md`** | Markdown | Executive report with WHOIS lifecycle dates, DNS records, JS endpoints, and findings |
| **`findings.json`** | JSON | Complete structured machine-readable dataset with provenance |
| **`js_endpoints.txt`** | Text | Line-separated endpoints extracted from JS and historical archives |
| **`js_endpoints.csv`** | CSV | Tabular endpoints with parent source mapping (`url`, `js_source`, `source`) |
| **`js_endpoints.json`** | JSON | Structured JS endpoint dataset |
| **`subdomains.txt`** | Text | Discovered subdomains for downstream tools (`httpx`, `nuclei`, `ffuf`) |
| **`subdomains.csv`** | CSV | Subdomains with source attribution and evidence |
| **`dns_records.txt`** | Text | Tab-separated DNS records by type (`A`, `AAAA`, `MX`, `NS`, `SOA`, `TXT`, `DMARC`) |
| **`dns_records.csv`** | CSV | Tabular DNS records with record type and source |
| **`vhosts.txt`** | Text | Virtual host candidates with status code and title |
| **`vhosts.csv`** | CSV | Tabular virtual host candidates with confidence ratings |
| **`historical_urls.txt`** | Text | Archived Wayback URLs |
| **`historical_urls.csv`** | CSV | Tabular historical URLs with interest flags |
| **`interesting_historical_urls.txt`** | Text | High-risk pattern matches (`.env`, `.bak`, `.sql`, config files) |
| **`documents.csv`** | CSV | Harvested document metadata (`filename`, `author`, `creator`, `title`, `url`) |
| **`ptr_records.csv`** | CSV | Reverse DNS sweep mappings (`ip`, `hostname`, `source`) |
| **`whois.json`** | JSON | Modern ICANN RDAP registration record |
| **`m365.json`** | JSON | Microsoft 365 / Entra ID tenant GUID, namespace type, and ADFS federation details |
| **`email_security.json`** | JSON | Inbound Email Security Gateway (SEG) classification and DMARC/SPF spoofing assessment |
| **`gateways.csv`** | CSV | Tabular discovered perimeter gateways and VPN portals (`host`, `vendor`, `product`, `url`) |
| **`gateways.txt`** | Text | Tab-separated list of identified perimeter remote access portals |
| **`takeovers.csv`** | CSV | Dangling CNAME subdomain takeover audit results (`subdomain`, `cname`, `provider`, `status`) |
| **`takeovers.txt`** | Text | Tab-separated identified takeover candidates |
| **`cloud_buckets.csv`** | CSV | Discovered cloud storage buckets across AWS, Azure, GCP with access status |
| **`cloud_buckets.txt`** | Text | Tab-separated discovered cloud buckets and URLs |
| **`services.csv`** | CSV | Tabular discovered network services and open ports (`ip`, `port`, `service`, `product`, `org`, `source`) |
| **`services.txt`** | Text | Tab-separated network services and port list (`ip:port\tservice\torg\tsource`) |
| **`services.json`** | JSON | Structured network service and port discovery dataset |
| **`certificates.csv`** | CSV | Tabular live TLS certificates and Certificate Transparency history (`common_name`, `issuer`, `valid_to`, `status`, `sans`) |
| **`certificates.txt`** | Text | Tab-separated certificate list (`common_name\tissuer\tvalid_to\tsource`) |
| **`certificates.json`** | JSON | Full structured dataset of live TLS certificate and CT log records |
| **`security_headers.csv`** | CSV | HTTP security header audit results with hygiene grades and defense scores |
| **`security_headers.txt`** | Text | Tab-separated security header hygiene grades and defense scores |
| **`username_profiles.csv`** | CSV | Verified social and developer profiles (`platform`, `url`, `status`) |
| **`breaches.csv`** | CSV | HaveIBeenPwned compromised accounts and exposed data classes |
| **`source_status.json`** | JSON | Status, latency, and item counts for each data provider |

---

## Environment Configuration

Configure optional API providers in `.env` or export environment variables:

```bash
# Search APIs (for person search and document discovery)
export SERPER_API_KEY="your-serper-key"  # Free 2,500 queries at serper.dev
export BRAVE_API_KEY="your-brave-key"
export BING_API_KEY="your-bing-key"
export GOOGLE_API_KEY="your-google-api-key"
export GOOGLE_CSE_ID="your-google-custom-search-engine-id"

# Breach Intelligence
export HIBP_API_KEY="your-hibp-key"

# Threat Intelligence & Internet Scanning APIs
export GITHUB_TOKEN="your-github-token"
export SHODAN_API_KEY="your-shodan-key"
export CENSYS_TOKEN="your-censys-pat"  # Censys Platform v3 PAT or CENSYS_API_ID / CENSYS_API_SECRET
export CENSYS_API_ID="your-censys-id"
export CENSYS_API_SECRET="your-censys-secret"

# Global OPSEC & Proxy Settings
export RECONX_PROXY="socks5://127.0.0.1:9050"

# Cache Configuration
export RECONX_CACHE=1
export RECONX_CACHE_TTL=86400
```

---

## Scope & Legal Disclaimer

ReconX is designed exclusively for authorized security research, educational purposes, and permitted penetration testing engagements. Always obtain explicit written authorization before assessing target networks or identities.
