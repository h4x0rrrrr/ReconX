"""Unified JSON, Markdown, CSV and category-file reporting with provenance, deduplication and cautious claims."""
from __future__ import annotations
import csv
import json
import os
from datetime import datetime, timezone
from typing import Any
from reconx.core.plugins import deduplicate

class Findings:
    def __init__(self, target: str, mode: str):
        self.target = target
        self.mode = mode
        self.generated_at = datetime.now(timezone.utc).isoformat()
        self.data: dict[str, Any] = {}
        self.flags: list[dict[str, str]] = []

    def add(self, section: str, value: Any) -> None:
        if isinstance(value, list) and value and all(isinstance(x, dict) for x in value) and any(any(k in x for k in ("url", "value", "host", "ip")) for x in value):
            value = deduplicate(value)
        self.data[section] = value

    def flag(self, severity: str, note: str) -> None:
        self.flags.append({"severity": severity, "note": note})

    def auto_flag_domain(self) -> None:
        interesting = self.data.get("interesting_historical_urls", [])
        if interesting:
            self.flag("medium", f"{len(interesting)} historical URL(s) match backup/config-like file patterns; review manually, no exposure is assumed.")

        dns = self.data.get("dns_records", {})
        if dns and not dns.get("DMARC"):
            self.flag("low", "No DMARC TXT record was observed by this DNS lookup; validate with authoritative DNS before drawing conclusions.")

        spf_values = [str(x.get("value", "")) if isinstance(x, dict) else str(x) for x in dns.get("SPF", [])]
        if any("~all" in x.lower() for x in spf_values):
            self.flag("info", "SPF includes softfail (~all); interpret in the context of the full email-security policy.")

        conventions = self.data.get("username_conventions", [])
        if conventions:
            self.flag("info", f"Document metadata yielded potential corporate username naming conventions: {', '.join(conventions[:3])}")

        for h in self.data.get("live_hosts", []):
            title = (h.get("title") or "").lower()
            server = (h.get("server") or "").lower()
            if any(x in title + " " + server for x in ("jenkins", "grafana", "kibana", "phpmyadmin", "adminer")):
                self.flag("info", f"Technology/title indicator on {h.get('host')}: {h.get('title') or server}. Verify access controls manually.")

        vhosts = self.data.get("vhosts", [])
        if vhosts:
            self.flag("low", f"{len(vhosts)} virtual-host candidate(s) detected via HTTP Host header fingerprinting. Verify manually.")

        # Email Security & DMARC flags
        email_sec = self.data.get("email_security", {})
        if email_sec and isinstance(email_sec, dict):
            dmarc = email_sec.get("dmarc", {})
            if dmarc.get("policy") == "missing":
                self.flag("high", f"No DMARC record published on {self.target}. Domain is vulnerable to direct email spoofing.")
            elif dmarc.get("policy") == "none":
                self.flag("medium", f"DMARC policy on {self.target} is set to p=none (monitoring only). Inbound spoofed messages are not rejected.")

        # Perimeter Gateway flags
        gateways = self.data.get("perimeter_gateways", [])
        if gateways and isinstance(gateways, list):
            for g in gateways:
                self.flag("info", f"Perimeter gateway identified on {g.get('host')}: {g.get('vendor')} {g.get('product')}. Review external access controls.")

        # Subdomain Takeover flags
        takeovers = self.data.get("takeovers", [])
        if takeovers and isinstance(takeovers, list):
            for t in takeovers:
                self.flag("high", f"Subdomain takeover risk on {t.get('subdomain')}: CNAME {t.get('cname')} points to unclaimed {t.get('provider')}. Verify immediately.")

        # Cloud Storage Bucket flags
        buckets = self.data.get("cloud_buckets", [])
        if buckets and isinstance(buckets, list):
            public_buckets = [b for b in buckets if "Public" in b.get("access", "")]
            if public_buckets:
                for b in public_buckets:
                    self.flag("high", f"Public cloud storage bucket exposed: {b.get('name')} ({b.get('provider')}) at {b.get('url')}.")
            for b in [x for x in buckets if "Protected" in x.get("access", "")][:3]:
                self.flag("info", f"Protected cloud storage bucket identified: {b.get('name')} ({b.get('provider')}).")

        # Security Headers flags
        sec_headers = self.data.get("security_headers", [])
        if sec_headers and isinstance(sec_headers, list):
            poor_hosts = [h for h in sec_headers if h.get("grade") in ("D", "F")]
            if poor_hosts:
                self.flag("low", f"{len(poor_hosts)} live host(s) received low security header grades (missing HSTS/CSP).")

        # Network Services & Open Ports flags (Shodan & Censys)
        net_svcs = self.data.get("network_services", [])
        if net_svcs and isinstance(net_svcs, list):
            self.flag("info", f"{len(net_svcs)} open port(s) and network service(s) identified via Shodan/Censys intelligence.")
            db_ports = {3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB", 1433: "MSSQL", 9200: "Elasticsearch", 11211: "Memcached"}
            remote_admin_ports = {21: "FTP", 23: "Telnet", 3389: "RDP", 445: "SMB", 5900: "VNC"}
            for s in net_svcs:
                port = s.get("port")
                if port in db_ports:
                    self.flag("high", f"Exposed database service port {port} ({db_ports[port]}) detected on {s.get('ip')} via {s.get('source')}.")
                elif port in (23, 445):
                    self.flag("high", f"Insecure administrative/sharing service port {port} ({remote_admin_ports.get(port, 'service')}) detected on {s.get('ip')} via {s.get('source')}.")
        # TLS / SSL Certificate flags
        live_cert = self.data.get("live_certificate")
        if live_cert and isinstance(live_cert, dict):
            status = live_cert.get("status")
            if status == "expired":
                self.flag("high", f"TLS certificate for {self.target} has EXPIRED on {live_cert.get('valid_to', '')[:10]}!")
            elif status == "expiring_soon":
                self.flag("medium", f"TLS certificate for {self.target} expires soon ({live_cert.get('days_remaining')} days remaining on {live_cert.get('valid_to', '')[:10]}).")
            if "Untrusted" in live_cert.get("issuer", "") or "Self-Signed" in live_cert.get("issuer", ""):
                self.flag("medium", f"Untrusted or self-signed TLS certificate detected on {self.target}: {live_cert.get('issuer')}.")

        # Unmasked Origin IPs (WAF / CDN bypass)
        origins = self.data.get("origin_ips", [])
        if origins and isinstance(origins, list):
            for o in origins:
                if o.get("confidence") == "High":
                    self.flag("high", f"Potential Origin IP unmasked bypassing {o.get('fronted_by_cdn')}: {o.get('ip')} ({o.get('evidence')}).")
                elif o.get("confidence") == "Medium":
                    self.flag("medium", f"Candidate Origin IP identified: {o.get('ip')} ({o.get('evidence')}).")

        # Correlated CVEs and CISA KEV
        vulns = self.data.get("vulnerabilities", [])
        if vulns and isinstance(vulns, list):
            for v in vulns:
                sev = "high" if v.get("severity") in ("CRITICAL", "HIGH") else "medium"
                cisa_tag = " [CISA KEV]" if v.get("cisa_kev") else ""
                self.flag(sev, f"{v.get('cve')}{cisa_tag} on {v.get('technology')} ({v.get('host')}): {v.get('title')}.")

        # NTLM Internal Identity disclosure
        ntlm = self.data.get("ntlm_disclosure", [])
        if ntlm and isinstance(ntlm, list):
            for n in ntlm:
                dom = n.get("dns_domain_name") or n.get("netbios_domain_name", "Unknown")
                srv = n.get("dns_computer_name") or n.get("netbios_computer_name", "Unknown")
                self.flag("medium", f"Internal Active Directory identity disclosed via NTLM challenge at {n.get('url')}: Domain={dom}, Host={srv}, OS={n.get('os_version', 'Windows')}.")

        # Sensitive GitHub Repos
        gh = self.data.get("github_intel", {})
        if gh and isinstance(gh, dict):
            sens = gh.get("sensitive_repos", [])
            if sens:
                self.flag("medium", f"Target GitHub organization '{gh.get('org')}' has {len(sens)} public repo(s) with infrastructure/secrets keywords (e.g. {sens[0].get('name')}).")

    def to_dict(self) -> dict[str, Any]:
        order = {"high": 0, "medium": 1, "low": 2, "info": 3}
        return {
            "tool": "ReconX",
            "version": "0.3.3",
            "target": self.target,
            "mode": self.mode,
            "generated_at": self.generated_at,
            "flags": sorted(self.flags, key=lambda x: order.get(x["severity"], 4)),
            "data": self.data,
        }

    def write_json(self, out_dir: str) -> str:
        path = os.path.join(out_dir, "findings.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2, ensure_ascii=False, default=str)
        return path

    def write_html(self, out_dir: str) -> str:
        from reconx.core.html_report import generate_html_report
        path = os.path.join(out_dir, "report.html")
        content = generate_html_report(self.to_dict())
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        return path

    def write_csv(self, out_dir: str) -> list[str]:
        """Export tabular finding types to individual CSV files."""
        generated_csvs = []

        # 1. Subdomains CSV
        subs = self.data.get("subdomains", [])
        if subs and isinstance(subs, list):
            csv_path = os.path.join(out_dir, "subdomains.csv")
            with open(csv_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["host", "sources", "evidence"])
                for s in subs:
                    sources = "; ".join(s.get("sources", [s.get("source", "")]))
                    writer.writerow([s.get("host", ""), sources, s.get("evidence", "")])
            generated_csvs.append(csv_path)

        # 2. DNS Records CSV
        dns_recs = self.data.get("dns_records", {})
        if dns_recs and isinstance(dns_recs, dict):
            csv_path = os.path.join(out_dir, "dns_records.csv")
            with open(csv_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["record_type", "value", "source"])
                for rtype, items in dns_recs.items():
                    for item in items:
                        val = item.get("value", "") if isinstance(item, dict) else str(item)
                        src = item.get("source", "dns") if isinstance(item, dict) else "dns"
                        writer.writerow([rtype, val, src])
            generated_csvs.append(csv_path)

        # 3. Username Profiles CSV
        profiles = self.data.get("results", [])
        if self.mode == "username" and profiles:
            csv_path = os.path.join(out_dir, "username_profiles.csv")
            with open(csv_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["platform", "url", "status", "http_status", "sources"])
                for p in profiles:
                    sources = "; ".join(p.get("sources", [p.get("source", "")]))
                    writer.writerow([p.get("platform", ""), p.get("url", ""), p.get("status", ""), p.get("http_status", ""), sources])
            generated_csvs.append(csv_path)

        # 4. Breaches CSV
        breaches = self.data.get("breaches", [])
        if breaches and isinstance(breaches, list):
            csv_path = os.path.join(out_dir, "breaches.csv")
            with open(csv_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["name", "title", "domain", "breach_date", "pwn_count", "data_classes"])
                for b in breaches:
                    dc = "; ".join(b.get("data_classes", []))
                    writer.writerow([b.get("name", ""), b.get("title", ""), b.get("domain", ""), b.get("breach_date", ""), b.get("pwn_count", 0), dc])
            generated_csvs.append(csv_path)

        # 5. Historical URLs CSV
        hist = self.data.get("historical_urls", [])
        if hist and isinstance(hist, list):
            csv_path = os.path.join(out_dir, "historical_urls.csv")
            with open(csv_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["url", "interesting", "source"])
                for h in hist:
                    writer.writerow([h.get("url", ""), h.get("interesting", False), h.get("source", "")])
            generated_csvs.append(csv_path)

        # 6. Virtual Hosts CSV
        vhosts = self.data.get("vhosts", [])
        if vhosts and isinstance(vhosts, list):
            csv_path = os.path.join(out_dir, "vhosts.csv")
            with open(csv_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["host", "url", "status", "title", "confidence"])
                for v in vhosts:
                    writer.writerow([v.get("host", ""), v.get("url", ""), v.get("status", ""), v.get("title", ""), v.get("confidence", "")])
            generated_csvs.append(csv_path)

        # 7. Document Metadata CSV
        docs = self.data.get("document_metadata", [])
        if docs and isinstance(docs, list):
            csv_path = os.path.join(out_dir, "documents.csv")
            with open(csv_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["filename", "author", "creator", "last_modified_by", "title", "url"])
                for d in docs:
                    writer.writerow([d.get("filename", ""), d.get("author", ""), d.get("creator", ""), d.get("last_modified_by", ""), d.get("title", ""), d.get("url", "")])
            generated_csvs.append(csv_path)

        # 8. PTR Records CSV
        ptrs = self.data.get("ptr_records", [])
        if ptrs and isinstance(ptrs, list):
            csv_path = os.path.join(out_dir, "ptr_records.csv")
            with open(csv_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["ip", "hostname", "source"])
                for r in ptrs:
                    writer.writerow([r.get("ip", ""), r.get("hostname", ""), r.get("source", "")])
            generated_csvs.append(csv_path)

        # 9. JS Endpoints CSV
        js_eps = self.data.get("js_endpoints", [])
        if js_eps and isinstance(js_eps, list):
            csv_path = os.path.join(out_dir, "js_endpoints.csv")
            with open(csv_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["url", "js_source", "source"])
                for ep in js_eps:
                    writer.writerow([ep.get("url", ""), ep.get("js_source", ""), ep.get("source", "")])
            generated_csvs.append(csv_path)

        # 10. Perimeter Gateways CSV
        gateways = self.data.get("perimeter_gateways", [])
        if gateways and isinstance(gateways, list):
            csv_path = os.path.join(out_dir, "gateways.csv")
            with open(csv_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["host", "url", "vendor", "product", "status", "evidence"])
                for g in gateways:
                    writer.writerow([g.get("host", ""), g.get("url", ""), g.get("vendor", ""), g.get("product", ""), g.get("status", ""), g.get("evidence", "")])
            generated_csvs.append(csv_path)

        # 11. Subdomain Takeovers CSV
        takeovers = self.data.get("takeovers", [])
        if takeovers and isinstance(takeovers, list):
            csv_path = os.path.join(out_dir, "takeovers.csv")
            with open(csv_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["subdomain", "cname", "provider", "status", "confidence", "url", "evidence"])
                for t in takeovers:
                    writer.writerow([t.get("subdomain", ""), t.get("cname", ""), t.get("provider", ""), t.get("status", ""), t.get("confidence", ""), t.get("url", ""), t.get("evidence", "")])
            generated_csvs.append(csv_path)

        # 12. Cloud Storage Buckets CSV
        buckets = self.data.get("cloud_buckets", [])
        if buckets and isinstance(buckets, list):
            csv_path = os.path.join(out_dir, "cloud_buckets.csv")
            with open(csv_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["name", "provider", "url", "status", "access"])
                for b in buckets:
                    writer.writerow([b.get("name", ""), b.get("provider", ""), b.get("url", ""), b.get("status", ""), b.get("access", "")])
            generated_csvs.append(csv_path)

        # 13. Security Headers CSV
        sec_headers = self.data.get("security_headers", [])
        if sec_headers and isinstance(sec_headers, list):
            csv_path = os.path.join(out_dir, "security_headers.csv")
            with open(csv_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["host", "url", "grade", "score", "missing_headers", "present_headers"])
                for sh in sec_headers:
                    writer.writerow([sh.get("host", ""), sh.get("url", ""), sh.get("grade", ""), sh.get("score", ""), "; ".join(sh.get("missing", [])), "; ".join(sh.get("present", []))])
            generated_csvs.append(csv_path)

        # 14. Network Services CSV (Shodan & Censys)
        net_svcs = self.data.get("network_services", [])
        if net_svcs and isinstance(net_svcs, list):
            csv_path = os.path.join(out_dir, "services.csv")
            with open(csv_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["ip", "port", "service", "product", "technologies", "org", "source", "evidence"])
                for s in net_svcs:
                    tech_str = "; ".join(s.get("technologies", [])) if s.get("technologies") else s.get("product", "")
                    writer.writerow([
                        s.get("ip", ""),
                        s.get("port", ""),
                        s.get("service", ""),
                        s.get("product", ""),
                        tech_str,
                        s.get("org", s.get("location", "")),
                        s.get("source", ""),
                        s.get("evidence", ""),
                    ])
            generated_csvs.append(csv_path)

        # 15. URLScan Records CSV
        urlscans = self.data.get("urlscan_records", [])
        if urlscans and isinstance(urlscans, list):
            csv_path = os.path.join(out_dir, "urlscan.csv")
            with open(csv_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["url", "domain", "ip", "title", "scan_id", "source"])
                for u in urlscans:
                    writer.writerow([u.get("url", ""), u.get("domain", ""), u.get("ip", ""), u.get("title", ""), u.get("scan_id", ""), u.get("source", "")])
            generated_csvs.append(csv_path)

        # 16. Certificates CSV (Live TLS & CT logs)
        certs = self.data.get("certificates", [])
        if certs and isinstance(certs, list):
            csv_path = os.path.join(out_dir, "certificates.csv")
            with open(csv_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["common_name", "issuer", "valid_from", "valid_to", "status", "days_remaining", "sans", "serial_number", "sha256_fingerprint", "source"])
                for c in certs:
                    sans_str = "; ".join(c.get("sans", []))
                    writer.writerow([
                        c.get("common_name", ""),
                        c.get("issuer", ""),
                        c.get("valid_from", ""),
                        c.get("valid_to", ""),
                        c.get("status", ""),
                        c.get("days_remaining", ""),
                        sans_str,
                        c.get("serial_number", ""),
                        c.get("sha256_fingerprint", ""),
                        c.get("source", ""),
                    ])
            generated_csvs.append(csv_path)

        # 17. Correlated CVEs & Vulnerabilities CSV
        vulns = self.data.get("vulnerabilities", [])
        if vulns and isinstance(vulns, list):
            csv_path = os.path.join(out_dir, "vulnerabilities.csv")
            with open(csv_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["cve", "severity", "cvss", "cisa_kev", "technology", "host", "port", "title", "advisory"])
                for v in vulns:
                    writer.writerow([
                        v.get("cve", ""),
                        v.get("severity", ""),
                        v.get("cvss", ""),
                        v.get("cisa_kev", False),
                        v.get("technology", ""),
                        v.get("host", ""),
                        v.get("port", ""),
                        v.get("title", ""),
                        v.get("advisory", ""),
                    ])
            generated_csvs.append(csv_path)

        # 18. Unmasked Origin IPs CSV
        origins = self.data.get("origin_ips", [])
        if origins and isinstance(origins, list):
            csv_path = os.path.join(out_dir, "origin_ips.csv")
            with open(csv_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["ip", "matched_host", "fronted_by_cdn", "confidence", "evidence", "source"])
                for o in origins:
                    writer.writerow([
                        o.get("ip", ""),
                        o.get("matched_host", ""),
                        o.get("fronted_by_cdn", ""),
                        o.get("confidence", ""),
                        o.get("evidence", ""),
                        o.get("source", ""),
                    ])
            generated_csvs.append(csv_path)

        # 19. ASN & BGP CIDR Ranges CSV
        asn_ranges = self.data.get("asn_ranges", [])
        if asn_ranges and isinstance(asn_ranges, list):
            csv_path = os.path.join(out_dir, "asn_ranges.csv")
            with open(csv_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["asn", "asn_name", "cidr", "country", "ip", "source"])
                for a in asn_ranges:
                    writer.writerow([
                        a.get("asn", ""),
                        a.get("asn_name", a.get("description", "")),
                        a.get("cidr", ""),
                        a.get("country", ""),
                        a.get("ip", ""),
                        a.get("source", ""),
                    ])
            generated_csvs.append(csv_path)

        return generated_csvs

    def write_category_files(self, out_dir: str, formats: set[str] | list[str] | None = None) -> None:
        """Writes domain-mode specific text and JSON output files for downstream tool pipelining."""
        if self.mode != "domain":
            return

        fmt_set = set(formats) if formats else {"all"}
        do_txt = "all" in fmt_set or "txt" in fmt_set
        do_json = "all" in fmt_set or "json" in fmt_set

        if not do_txt and not do_json:
            return

        # Subdomains .txt
        if do_txt:
            subs = self.data.get("subdomains", [])
            with open(os.path.join(out_dir, "subdomains.txt"), "w", encoding="utf-8") as f:
                for s in subs:
                    f.write(f"{s.get('host', '')}\n")

            # DNS records .txt
            dns_recs = self.data.get("dns_records", {})
            with open(os.path.join(out_dir, "dns_records.txt"), "w", encoding="utf-8") as f:
                for rtype, items in sorted(dns_recs.items()):
                    for it in items:
                        val = it.get("value", "") if isinstance(it, dict) else str(it)
                        f.write(f"{rtype}\t{val}\n")

            # Historical URLs .txt
            hist = self.data.get("historical_urls", [])
            with open(os.path.join(out_dir, "historical_urls.txt"), "w", encoding="utf-8") as f:
                for h in hist:
                    f.write(f"{h.get('url', '')}\n")

            # Interesting Historical URLs .txt
            interesting = self.data.get("interesting_historical_urls", [])
            with open(os.path.join(out_dir, "interesting_historical_urls.txt"), "w", encoding="utf-8") as f:
                for h in interesting:
                    f.write(f"{h.get('url', '')}\n")

            # Vhosts .txt
            vhosts = self.data.get("vhosts", [])
            with open(os.path.join(out_dir, "vhosts.txt"), "w", encoding="utf-8") as f:
                for v in vhosts:
                    f.write(f"{v.get('host', '')}\t{v.get('status', '')}\t{v.get('title', '')}\n")

        # WHOIS .json
        if do_json:
            whois = self.data.get("whois", {})
            with open(os.path.join(out_dir, "whois.json"), "w", encoding="utf-8") as f:
                json.dump(whois, f, indent=2, ensure_ascii=False)

            # M365 Identity .json
            m365 = self.data.get("m365_identity", {})
            if m365 and isinstance(m365, dict) and m365.get("is_m365"):
                with open(os.path.join(out_dir, "m365.json"), "w", encoding="utf-8") as f:
                    json.dump(m365, f, indent=2, ensure_ascii=False)

            # Email Security .json
            email_sec = self.data.get("email_security", {})
            if email_sec and isinstance(email_sec, dict):
                with open(os.path.join(out_dir, "email_security.json"), "w", encoding="utf-8") as f:
                    json.dump(email_sec, f, indent=2, ensure_ascii=False)

        # Perimeter Gateways .txt & .json
        gateways = self.data.get("perimeter_gateways", [])
        if gateways and isinstance(gateways, list):
            if do_txt:
                with open(os.path.join(out_dir, "gateways.txt"), "w", encoding="utf-8") as f:
                    for g in gateways:
                        f.write(f"{g.get('host', '')}\t{g.get('vendor', '')}\t{g.get('product', '')}\t{g.get('url', '')}\n")
            if do_json:
                with open(os.path.join(out_dir, "gateways.json"), "w", encoding="utf-8") as f:
                    json.dump(gateways, f, indent=2, ensure_ascii=False)

        # Subdomain Takeovers .txt & .json
        takeovers = self.data.get("takeovers", [])
        if takeovers and isinstance(takeovers, list):
            if do_txt:
                with open(os.path.join(out_dir, "takeovers.txt"), "w", encoding="utf-8") as f:
                    for t in takeovers:
                        f.write(f"{t.get('subdomain', '')}\t{t.get('cname', '')}\t{t.get('provider', '')}\n")
            if do_json:
                with open(os.path.join(out_dir, "takeovers.json"), "w", encoding="utf-8") as f:
                    json.dump(takeovers, f, indent=2, ensure_ascii=False)

        # Cloud Storage Buckets .txt & .json
        buckets = self.data.get("cloud_buckets", [])
        if buckets and isinstance(buckets, list):
            if do_txt:
                with open(os.path.join(out_dir, "cloud_buckets.txt"), "w", encoding="utf-8") as f:
                    for b in buckets:
                        f.write(f"{b.get('name', '')}\t{b.get('provider', '')}\t{b.get('access', '')}\t{b.get('url', '')}\n")
            if do_json:
                with open(os.path.join(out_dir, "cloud_buckets.json"), "w", encoding="utf-8") as f:
                    json.dump(buckets, f, indent=2, ensure_ascii=False)

        # Security Headers .txt & .json
        sec_headers = self.data.get("security_headers", [])
        if sec_headers and isinstance(sec_headers, list):
            if do_txt:
                with open(os.path.join(out_dir, "security_headers.txt"), "w", encoding="utf-8") as f:
                    for sh in sec_headers:
                        f.write(f"{sh.get('host', '')}\tGrade: {sh.get('grade', '')}\tScore: {sh.get('score', '')}\n")
            if do_json:
                with open(os.path.join(out_dir, "security_headers.json"), "w", encoding="utf-8") as f:
                    json.dump(sec_headers, f, indent=2, ensure_ascii=False)

        # JS Endpoints .txt and .json
        js_eps = self.data.get("js_endpoints", [])
        if js_eps and isinstance(js_eps, list):
            if do_txt:
                with open(os.path.join(out_dir, "js_endpoints.txt"), "w", encoding="utf-8") as f:
                    for ep in js_eps:
                        f.write(f"{ep.get('url', '')}\n")
            if do_json:
                with open(os.path.join(out_dir, "js_endpoints.json"), "w", encoding="utf-8") as f:
                    json.dump(js_eps, f, indent=2, ensure_ascii=False)

        # Network Services .txt and .json (Shodan & Censys)
        net_svcs = self.data.get("network_services", [])
        if net_svcs and isinstance(net_svcs, list):
            if do_txt:
                with open(os.path.join(out_dir, "services.txt"), "w", encoding="utf-8") as f:
                    for s in net_svcs:
                        svc_desc = s.get("service") or s.get("product") or "unknown"
                        tech_desc = f" [{'; '.join(s.get('technologies', []))}]" if s.get("technologies") else ""
                        org_desc = s.get("org") or s.get("location") or ""
                        f.write(f"{s.get('ip', '')}:{s.get('port', '')}\t{svc_desc}{tech_desc}\t{org_desc}\t{s.get('source', '')}\n")
            if do_json:
                with open(os.path.join(out_dir, "services.json"), "w", encoding="utf-8") as f:
                    json.dump(net_svcs, f, indent=2, ensure_ascii=False)

        # URLScan .json
        if do_json:
            urlscans = self.data.get("urlscan_records", [])
            if urlscans and isinstance(urlscans, list):
                with open(os.path.join(out_dir, "urlscan.json"), "w", encoding="utf-8") as f:
                    json.dump(urlscans, f, indent=2, ensure_ascii=False)

        # Certificates .txt and .json
        certs = self.data.get("certificates", [])
        if certs and isinstance(certs, list):
            if do_txt:
                with open(os.path.join(out_dir, "certificates.txt"), "w", encoding="utf-8") as f:
                    for c in certs:
                        f.write(f"{c.get('common_name', '')}\t{c.get('issuer', '')}\t{c.get('valid_to', '')}\t{c.get('source', '')}\n")
            if do_json:
                with open(os.path.join(out_dir, "certificates.json"), "w", encoding="utf-8") as f:
                    json.dump(certs, f, indent=2, ensure_ascii=False)

        # Source status .json
        if do_json:
            status = self.data.get("source_status", [])
            with open(os.path.join(out_dir, "source_status.json"), "w", encoding="utf-8") as f:
                json.dump(status, f, indent=2, ensure_ascii=False)

    def write_markdown(self, out_dir: str) -> str:
        path = os.path.join(out_dir, "REPORT.md")
        lines = [
            f"# ReconX Report — {self.target}",
            f"- Generated: `{self.generated_at}`",
            f"- Mode: `{self.mode}`",
            "",
            "## Summary",
        ]
        for key, value in self.data.items():
            if isinstance(value, list):
                lines.append(f"- **{key.replace('_', ' ').title()}**: {len(value)}")
            elif isinstance(value, dict):
                lines.append(f"- **{key.replace('_', ' ').title()}**: {sum(len(v) for v in value.values() if isinstance(v, list))} record(s) across {len(value)} field(s)")
            else:
                lines.append(f"- **{key.replace('_', ' ').title()}**: {value}")

        lines += ["", "## Findings"]
        if self.flags:
            order = {"high": 0, "medium": 1, "low": 2, "info": 3}
            for f in sorted(self.flags, key=lambda x: order.get(x["severity"], 4)):
                lines.append(f"- **{f['severity'].upper()}** — {f['note']}")
        else:
            lines.append("- No automatic flags. This is not proof that no issues exist.")

        # WHOIS section for domain mode
        whois = self.data.get("whois")
        if isinstance(whois, dict) and whois.get("registrar"):
            lines += [
                "",
                "## Domain Registration (RDAP / WHOIS)",
                f"- **Registrar**: {whois.get('registrar', 'Unknown')}",
                f"- **Created**: `{whois.get('created_date', 'Unknown')}`",
                f"- **Expires**: `{whois.get('expiration_date', 'Unknown')}`",
                f"- **Updated**: `{whois.get('updated_date', 'Unknown')}`",
                f"- **Name Servers**: {', '.join(whois.get('nameservers', [])) or 'None'}",
                f"- **DNSSEC**: {'Signed' if whois.get('dnssec') else 'Unsigned'}",
            ]

        # DNS Records breakdown
        dns_recs = self.data.get("dns_records")
        if isinstance(dns_recs, dict) and any(dns_recs.values()):
            lines += ["", "## DNS Records"]
            for rtype, recs in sorted(dns_recs.items()):
                if recs:
                    lines.append(f"### {rtype}")
                    for r in recs[:25]:
                        val = r.get("value", "") if isinstance(r, dict) else str(r)
                        src = r.get("source", "dns") if isinstance(r, dict) else "dns"
                        lines.append(f"- `{val}` — source: {src}")
                    if len(recs) > 25:
                        lines.append(f"- … {len(recs) - 25} more; see dns_records.txt / findings.json")

        # Microsoft 365 / Cloud Identity Section
        m365 = self.data.get("m365_identity")
        if isinstance(m365, dict) and m365.get("is_m365"):
            lines += [
                "",
                "## Microsoft 365 / Cloud Identity Posture",
                f"- **Organization Status**: Active Microsoft 365 / Entra ID Organization",
                f"- **Azure Tenant GUID**: `{m365.get('tenant_id') or 'Undisclosed'}`",
                f"- **Namespace Type**: `{m365.get('namespace_type', 'Unknown')}`",
                f"- **Identity Architecture**: {'Hybrid On-Premises ADFS / STS Federation' if m365.get('is_federated') else 'Pure Managed Cloud (Azure AD Native)'}",
            ]
            if m365.get("federation_brand"):
                lines.append(f"- **Federation Brand**: {m365.get('federation_brand')}")
            if m365.get("federation_auth_url"):
                lines.append(f"- **Federation STS Auth URL**: `{m365.get('federation_auth_url')}`")

        # Email Security & DMARC Section
        email_sec = self.data.get("email_security")
        if isinstance(email_sec, dict) and email_sec.get("seg_vendor"):
            dmarc = email_sec.get("dmarc", {})
            spf = email_sec.get("spf", {})
            lines += [
                "",
                "## Email Security Gateway (SEG) & DMARC Defense Posture",
                f"- **Inbound Email Security Gateway (SEG)**: **{email_sec.get('seg_vendor')}**",
                f"- **Mail Exchanger (MX) Hosts**: {', '.join(email_sec.get('mx_hosts', [])) or 'None'}",
                f"- **DMARC Spoofing Risk**: **{dmarc.get('spoofing_risk', 'Unknown').upper()}**",
                f"- **DMARC Policy**: `{dmarc.get('policy', 'N/A')}` (pct: {dmarc.get('pct', 100)}%)",
                f"- **DMARC Assessment**: {dmarc.get('compliance', 'N/A')}",
            ]
            if dmarc.get("record"):
                lines.append(f"- **DMARC Record**: `{dmarc.get('record')}`")
            if spf.get("record"):
                lines.append(f"- **SPF Record**: `{spf.get('record')}` (Qualifier: `{spf.get('qualifier', 'N/A')}`)")

        # Discovered Network Services & Open Ports Section (Shodan & Censys)
        net_svcs = self.data.get("network_services")
        if isinstance(net_svcs, list) and net_svcs:
            lines += ["", "## Discovered Network Services & Open Ports (Shodan & Censys)"]
            for s in net_svcs[:40]:
                svc_desc = s.get("service") or s.get("product") or "unknown"
                org_info = f" (Org: {s.get('org')})" if s.get("org") else ""
                tech_info = f" · Technologies: `{', '.join(s.get('technologies', []))}`" if s.get("technologies") else ""
                lines.append(f"- **{s.get('ip')}:{s.get('port')}** — {svc_desc}{org_info}{tech_info} · Source: `{s.get('source')}` · {s.get('evidence')}")
            if len(net_svcs) > 40:
                lines.append(f"- … {len(net_svcs) - 40} more; see services.csv / services.txt / findings.json")

        # Identified Technology Stack & Frameworks
        tech_list = self.data.get("technologies")
        if isinstance(tech_list, list) and tech_list:
            lines += ["", "## Identified Technology Stack & Frameworks"]
            for t in tech_list:
                lines.append(f"- `{t}`")

        # TLS / SSL Certificates & CT Intelligence
        live_cert = self.data.get("live_certificate")
        certs = self.data.get("certificates", [])
        if live_cert or certs:
            lines += ["", "## TLS / SSL Certificates & Certificate Transparency (CT)"]
            if live_cert:
                lines += [
                    f"- **Live TLS Certificate**: `{live_cert.get('common_name')}`",
                    f"  - **Issuer**: {live_cert.get('issuer')}",
                    f"  - **Validity**: `{live_cert.get('valid_from', '')[:10]}` to `{live_cert.get('valid_to', '')[:10]}` ({live_cert.get('days_remaining')} days remaining — **{live_cert.get('status', '').upper()}**)",
                    f"  - **SHA-256 Fingerprint**: `{live_cert.get('sha256_fingerprint')}`",
                    f"  - **Subject Alternative Names (SANs)**: {', '.join(live_cert.get('sans', [])) or 'None'}",
                ]
            if certs:
                lines.append(f"\n### Certificate Transparency History ({len(certs)} records)")
                for c in certs[:25]:
                    lines.append(f"- **{c.get('common_name')}** — Issuer: `{c.get('issuer')}` · Valid to: `{c.get('valid_to', '')[:10]}` · Source: `{c.get('source')}`")
                if len(certs) > 25:
                    lines.append(f"- … {len(certs) - 25} more; see certificates.csv / certificates.txt / findings.json")

        # Perimeter Gateways Section
        gateways = self.data.get("perimeter_gateways")
        if isinstance(gateways, list) and gateways:
            lines += ["", "## Perimeter Gateways & Remote Access Portals"]
            for g in gateways:
                lines.append(f"- **{g.get('vendor')} {g.get('product')}** on `{g.get('host')}` — HTTP {g.get('status')} ({g.get('url')}) · {g.get('evidence')}")

        # Subdomain Takeovers Section
        takeovers = self.data.get("takeovers")
        if isinstance(takeovers, list) and takeovers:
            lines += ["", "## Subdomain Takeovers & Dangling DNS Risks"]
            for t in takeovers:
                lines.append(f"- **HIGH RISK**: `{t.get('subdomain')}` CNAME -> `{t.get('cname')}` ({t.get('provider')}) · HTTP {t.get('status')} · {t.get('evidence')}")

        # Cloud Storage Buckets Section
        buckets = self.data.get("cloud_buckets")
        if isinstance(buckets, list) and buckets:
            lines += ["", "## Discovered Cloud Storage Buckets (AWS / Azure / GCP)"]
            for b in buckets:
                lines.append(f"- **{b.get('access')}**: `{b.get('name')}` ({b.get('provider')}) — [{b.get('url')}]({b.get('url')}) · HTTP {b.get('status')}")

        # Security Headers Section
        sec_headers = self.data.get("security_headers")
        if isinstance(sec_headers, list) and sec_headers:
            lines += ["", "## HTTP Security Headers & Transport Posture"]
            for sh in sec_headers[:25]:
                missing_str = f" · Missing: {', '.join(sh.get('missing', []))}" if sh.get('missing') else ""
                lines.append(f"- **Grade {sh.get('grade')}** ({sh.get('score')}/100) on `{sh.get('host')}` ({sh.get('url')}){missing_str}")

        # Correlated Vulnerabilities & CVEs
        vulns = self.data.get("vulnerabilities")
        if isinstance(vulns, list) and vulns:
            lines += ["", "## Correlated Vulnerabilities & CVE Advisories"]
            for v in vulns:
                cisa_tag = " [CISA KEV]" if v.get("cisa_kev") else ""
                lines.append(f"- **{v.get('severity')}** ({v.get('cvss')}) `{v.get('cve')}`{cisa_tag} on `{v.get('technology')}`: {v.get('title')} — [{v.get('advisory')}]({v.get('advisory')})")

        # Unmasked Origin IPs (WAF Bypass)
        origins = self.data.get("origin_ips")
        if isinstance(origins, list) and origins:
            lines += ["", "## Unmasked Origin IPs (WAF / CDN Bypass Candidates)"]
            for o in origins:
                lines.append(f"- **{o.get('confidence')} Confidence**: `{o.get('ip')}` unmasked bypassing {o.get('fronted_by_cdn')} · Host: `{o.get('matched_host')}` · {o.get('evidence')}")

        # ASN & BGP Routing Blocks
        asns = self.data.get("asn_ranges")
        if isinstance(asns, list) and asns:
            lines += ["", "## Autonomous Systems & BGP Routing Blocks"]
            for a in asns:
                lines.append(f"- **{a.get('asn')}** (`{a.get('cidr')}`) — {a.get('asn_name', a.get('description', ''))} ({a.get('country')})")

        # NTLM Internal Domain Disclosure
        ntlm_items = self.data.get("ntlm_disclosure")
        if isinstance(ntlm_items, list) and ntlm_items:
            lines += ["", "## Active Directory & NTLM Challenge Disclosures"]
            for n in ntlm_items:
                dom = n.get("dns_domain_name") or n.get("netbios_domain_name", "Unknown")
                srv = n.get("dns_computer_name") or n.get("netbios_computer_name", "Unknown")
                lines.append(f"- Domain: `{dom}` · Host: `{srv}` · OS: `{n.get('os_version', 'Windows')}` · Endpoint: {n.get('url')}")

        # GitHub Org Intelligence
        gh = self.data.get("github_intel")
        if isinstance(gh, dict) and gh:
            lines += ["", f"## GitHub Organization Intelligence ({gh.get('org')})"]
            lines.append(f"- Organization: **{gh.get('name') or gh.get('org')}** — [{gh.get('html_url')}]({gh.get('html_url')})")
            lines.append(f"- Public Repositories: {gh.get('public_repos', 0)} · Languages: {', '.join(gh.get('languages', []))}")
            sens = gh.get("sensitive_repos", [])
            if sens:
                lines.append(f"- **Sensitive Infra Repositories ({len(sens)}):**")
                for s in sens[:10]:
                    lines.append(f"    - [{s.get('name')}]({s.get('url')}) — {s.get('description') or 'No description'}")

        # Breach section
        breaches = self.data.get("breaches")
        if isinstance(breaches, list) and breaches:
            lines += ["", "## Breach Intelligence (HaveIBeenPwned)"]
            for b in breaches:
                dc = ", ".join(b.get("data_classes", []))
                lines.append(f"- **{b.get('title', b.get('name'))}** ({b.get('domain')}) · Breach Date: {b.get('breach_date')} · Compromised: {b.get('pwn_count', 0):,} accounts · Exposed: {dc}")

        # Document metadata & username conventions
        doc_meta = self.data.get("document_metadata")
        conventions = self.data.get("username_conventions")
        if conventions:
            lines += ["", "## Inferred Username Conventions"]
            for conv in conventions:
                lines.append(f"- `{conv}`")
        if isinstance(doc_meta, list) and doc_meta:
            lines += ["", "## Harvested Document Metadata"]
            for d in doc_meta[:30]:
                author = d.get("author") or d.get("creator") or "Unknown"
                lines.append(f"- **{d.get('filename')}** — Author: `{author}` · Title: {d.get('title', 'N/A')} · URL: {d.get('url')}")

        # Reverse DNS / PTR records
        ptrs = self.data.get("ptr_records")
        if isinstance(ptrs, list) and ptrs:
            lines += ["", "## Reverse DNS (PTR) Infrastructure"]
            for p in ptrs[:40]:
                lines.append(f"- `{p.get('ip')}` -> **{p.get('hostname')}**")
            infra_cat = self.data.get("infrastructure_categories", {})
            if infra_cat:
                lines.append("")
                lines.append("### Categorized Infrastructure")
                for cat, items in infra_cat.items():
                    lines.append(f"- **{cat.replace('_', ' ').title()}**: {', '.join(items[:10])}")

        # Vendor and tracker correlations
        trackers = self.data.get("vendor_trackers")
        if isinstance(trackers, list) and trackers:
            lines += ["", "## Vendor & Supply-Chain Correlation"]
            relationships = self.data.get("tracker_relationships", {})
            for name, urls in relationships.items():
                lines.append(f"- **{name}** observed on {len(urls)} page(s)")

        # Virtual hosts
        vhosts = self.data.get("vhosts")
        if isinstance(vhosts, list) and vhosts:
            lines += ["", "## Virtual Host Candidates (Host Header Comparison)"]
            for v in vhosts[:30]:
                lines.append(f"- `{v.get('host')}` — HTTP {v.get('status')} · Title: {v.get('title', 'None')} · {v.get('evidence', '')}")

        # Discovered JavaScript Endpoints
        js_eps = self.data.get("js_endpoints")
        if isinstance(js_eps, list) and js_eps:
            lines += ["", "## Discovered JavaScript Endpoints"]
            for ep in js_eps[:50]:
                lines.append(f"- `{ep.get('url')}` — source: {ep.get('js_source', ep.get('source', 'js_recon'))}")
            if len(js_eps) > 50:
                lines.append(f"- … {len(js_eps) - 50} more; see js_endpoints.txt / findings.json")

        # JavaScript Secret Indicators
        js_secrets = self.data.get("js_secret_indicators")
        if isinstance(js_secrets, list) and js_secrets:
            lines += ["", "## JavaScript Secret Indicators (Redacted)"]
            for s in js_secrets[:25]:
                lines.append(f"- **{s.get('type')}** in `{s.get('js_source')}` ({s.get('match_preview')})")

        # Username / Person modes
        if self.mode == "username":
            rows = self.data.get("results", [])
            lines += ["", "## Verified Username Profiles"]
            if rows:
                for r in rows:
                    sources = ", ".join(r.get("sources", [r.get("source", "unknown")]))
                    lines.append(f"- **{r.get('platform', 'Platform')}** — [{r.get('url', 'profile')}]({r.get('url', '')}) · HTTP {r.get('http_status', '?')} · source: {sources}")
            else:
                lines.append("- No profiles passed the strict verification checks. Candidates and ambiguous responses are intentionally hidden.")
        elif self.mode == "person":
            rows = self.data.get("results", [])
            lines += ["", "## Filtered Public Search Results"]
            if rows:
                for r in rows:
                    lines.append(f"- **[{r.get('title') or r.get('url')}]({r.get('url')})** — {r.get('snippet', '')} · source: {', '.join(r.get('sources', []))}")
            else:
                lines.append("- No results met all supplied filters. Configure search API keys to enable live search.")
        else:
            for key in ("subdomains", "live_hosts", "interesting_historical_urls", "tls_sans"):
                rows = self.data.get(key)
                if isinstance(rows, list) and rows:
                    lines += ["", f"## {key.replace('_', ' ').title()}"]
                    for r in rows[:150]:
                        if isinstance(r, dict):
                            value = r.get("host") or r.get("url") or r.get("value") or r.get("prefix") or json.dumps(r, ensure_ascii=False)
                            source = ", ".join(r.get("sources", [r.get("source", "unknown")]))
                            lines.append(f"- `{value}` — source: {source}")
                        else:
                            lines.append(f"- `{r}`")
                    if len(rows) > 150:
                        lines.append(f"- … {len(rows) - 150} more; see findings.json")

        lines += [
            "",
            "## Provenance and limitations",
            "- Sources are attributed per finding where available; duplicate values are merged.",
            "- API/provider failures are reported under `source_status`; failure is not evidence of absence.",
            "- Username profiles are shown only when strict HTTP/content checks pass. A zero-result scan does not prove the username is absent.",
            "- Run only against assets and identities you are authorized to assess.",
        ]

        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        return path
