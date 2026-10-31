"""Pipeline Exporter & Tool Integrations.

Generates pre-formatted target lists and configuration scopes for downstream tools:
- Nuclei target lists (targets_nuclei.txt)
- Web targets (targets_web.txt)
- Service targets (targets_services.txt)
- Burp Suite project scope JSON (burp_scope.json)
"""
from __future__ import annotations

import json
import os
import re
from typing import Any

def export_pipeline_targets(out_dir: str, findings: Any) -> list[str]:
    """Export tool integration artifacts to output directory."""
    generated = []
    data = findings.data
    target = findings.target

    # 1. targets_nuclei.txt & targets_web.txt
    urls = set()
    for h in data.get("live_hosts", []):
        u = h.get("url")
        if u:
            urls.add(u.strip())

    for s in data.get("subdomains", []):
        host = s.get("host")
        if host:
            urls.add(f"https://{host}")
            urls.add(f"http://{host}")

    for svc in data.get("network_services", []):
        port = svc.get("port")
        ip = svc.get("ip")
        if port in (80, 8080, 8000, 5000, 3000):
            urls.add(f"http://{ip}:{port}")
        elif port in (443, 8443, 9443):
            urls.add(f"https://{ip}:{port}")

    if urls:
        nuclei_path = os.path.join(out_dir, "targets_nuclei.txt")
        sorted_urls = sorted(list(urls))
        with open(nuclei_path, "w", encoding="utf-8") as f:
            f.write("\n".join(sorted_urls) + "\n")
        generated.append(nuclei_path)

        web_path = os.path.join(out_dir, "targets_web.txt")
        with open(web_path, "w", encoding="utf-8") as f:
            f.write("\n".join(sorted_urls) + "\n")
        generated.append(web_path)

    # 2. targets_services.txt (IP:PORT)
    services = set()
    for svc in data.get("network_services", []):
        ip = svc.get("ip")
        port = svc.get("port")
        if ip and port:
            services.add(f"{ip}:{port}")

    if services:
        svc_path = os.path.join(out_dir, "targets_services.txt")
        with open(svc_path, "w", encoding="utf-8") as f:
            f.write("\n".join(sorted(list(services))) + "\n")
        generated.append(svc_path)

    # 3. burp_scope.json (Burp Suite Pro/Community Scope JSON)
    escaped_target = re.escape(target).replace(r"\.", r"\.")
    burp_config = {
        "target": {
            "scope": {
                "advanced_mode": True,
                "include": [
                    {
                        "enabled": True,
                        "host": f"^.*\\.{escaped_target}$",
                        "protocol": "any",
                    },
                    {
                        "enabled": True,
                        "host": f"^{escaped_target}$",
                        "protocol": "any",
                    },
                ],
                "exclude": [],
            }
        }
    }
    burp_path = os.path.join(out_dir, "burp_scope.json")
    with open(burp_path, "w", encoding="utf-8") as f:
        json.dump(burp_config, f, indent=2)
    generated.append(burp_path)

    return generated
