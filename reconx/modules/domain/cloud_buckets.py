"""Cloud Storage Bucket Permutation & Public Exposure Auditor (AWS S3, Azure Blob, GCP)."""
from __future__ import annotations
import asyncio
import re
from typing import Any, Mapping
import httpx

BUCKET_SUFFIXES = [
    "",
    "-assets",
    "-backup",
    "-backups",
    "-data",
    "-dev",
    "-staging",
    "-prod",
    "-internal",
    "-public",
    "-media",
    "-files",
    "-storage",
    "-logs",
    "-static",
    "-cdn",
    "-app",
    "-upload",
    "-uploads",
    "-docs",
]

def extract_bucket_names_from_urls(urls: list[str]) -> list[str]:
    """Extract candidate bucket / storage account names from passive URLs."""
    names = set()
    for u in urls:
        if not u or not isinstance(u, str):
            continue
        # AWS S3: https://<bucket>.s3... or https://s3.amazonaws.com/<bucket> or https://s3-<region>.amazonaws.com/<bucket>
        m = re.search(r"https?://([a-z0-9.-]+)\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com", u, re.I)
        if m and m.group(1).lower() not in ("s3", "s3-external-1"):
            names.add(m.group(1).lower())
        m2 = re.search(r"https?://s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com/([a-z0-9.-]+)", u, re.I)
        if m2:
            names.add(m2.group(1).lower().split("/")[0])
        # GCP: https://storage.googleapis.com/<bucket> or https://<bucket>.storage.googleapis.com
        m3 = re.search(r"https?://storage\.googleapis\.com/([a-z0-9.-]+)", u, re.I)
        if m3:
            names.add(m3.group(1).lower().split("/")[0])
        m4 = re.search(r"https?://([a-z0-9.-]+)\.storage\.googleapis\.com", u, re.I)
        if m4 and m4.group(1).lower() != "storage":
            names.add(m4.group(1).lower())
        # Azure: https://<account>.blob.core.windows.net
        m5 = re.search(r"https?://([a-z0-9]+)\.blob\.core\.windows\.net", u, re.I)
        if m5:
            names.add(m5.group(1).lower())
    return sorted(names)

def generate_bucket_candidates(
    domain: str,
    discovered_subdomains: list[str] | None = None,
    extra_names: list[str] | None = None,
) -> list[str]:
    """Generate deterministic brand-based and domain-based candidate bucket names."""
    domain = domain.strip().lower().rstrip(".")
    parts = domain.split(".")

    # Extract primary brand token
    brand = parts[0] if parts else domain
    if brand in ("www", "web", "api", "app", "dev", "m", "mail") and len(parts) >= 3:
        brand = parts[1]
    brand_clean = re.sub(r"[^a-z0-9-]", "", brand)

    stems = set()
    if brand_clean:
        stems.add(brand_clean)

    # Clean domain without dots (e.g. "xxnxhealth" from "xxnx.health")
    nodots = re.sub(r"[^a-z0-9]", "", domain)
    if nodots and nodots != brand_clean:
        stems.add(nodots)

    # Hyphenated domain stems (e.g. "xxnx-health" and "health-xxnx")
    if len(parts) >= 2:
        clean_parts = [re.sub(r"[^a-z0-9]", "", p) for p in parts if p]
        hyphenated = "-".join(clean_parts)
        if hyphenated:
            stems.add(hyphenated)
        if len(clean_parts) == 2:
            stems.add(f"{clean_parts[1]}-{clean_parts[0]}")

    candidates = set()
    for stem in stems:
        for suffix in BUCKET_SUFFIXES:
            cand = f"{stem}{suffix}"
            if 3 <= len(cand) <= 63:
                candidates.add(cand)

    # Domain with dots (valid in S3 and GCP static hosting)
    if 3 <= len(domain) <= 63:
        candidates.add(domain)

    # Discovered subdomains permutations
    if discovered_subdomains:
        for sub in discovered_subdomains:
            sub = sub.strip().lower().rstrip(".")
            if sub and 3 <= len(sub) <= 63 and "." in sub:
                candidates.add(sub)
            sub_parts = sub.split(".")
            if sub_parts and sub_parts[0] not in ("www", brand_clean):
                prefix = re.sub(r"[^a-z0-9]", "", sub_parts[0])
                if prefix and brand_clean:
                    cand1 = f"{brand_clean}-{prefix}"
                    cand2 = f"{prefix}-{brand_clean}"
                    if 3 <= len(cand1) <= 63:
                        candidates.add(cand1)
                    if 3 <= len(cand2) <= 63:
                        candidates.add(cand2)

    # Passively discovered bucket names
    if extra_names:
        for ex in extra_names:
            ex_clean = ex.strip().lower()
            if 3 <= len(ex_clean) <= 63:
                candidates.add(ex_clean)

    return sorted(candidates)

async def audit_cloud_buckets(
    domain: str,
    client: httpx.AsyncClient,
    cfg: Mapping[str, Any] | None = None,
    discovered_subdomains: list[str] | None = None,
    extra_names: list[str] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, str]]:
    """Probe candidate bucket permutations on AWS S3, Azure Blob, and GCP Storage."""
    candidates = generate_bucket_candidates(
        domain,
        discovered_subdomains=discovered_subdomains,
        extra_names=extra_names,
    )
    detected: list[dict[str, Any]] = []
    concurrency = int((cfg or {}).get("concurrency", 12)) if cfg else 12
    sem = asyncio.Semaphore(concurrency)

    # Fast request helper with fallback to head for mock compatibility
    async def _send_req(url: str, params: dict | None = None):
        try:
            return await client.get(url, params=params, timeout=5.0)
        except AttributeError:
            return await client.head(url, timeout=5.0)

    async def check_aws(name: str):
        # Use path-style URL for names containing dots to avoid TLS wildcard certificate mismatch
        if "." in name:
            url = f"https://s3.amazonaws.com/{name}"
        else:
            url = f"https://{name}.s3.amazonaws.com"

        async with sem:
            try:
                r = await _send_req(url)
                if r.status_code == 404:
                    return

                status = r.status_code
                headers = getattr(r, "headers", {}) or {}
                region = headers.get("x-amz-bucket-region") if hasattr(headers, "get") else None
                final_url = url

                # Handle cross-regional redirection (301/307)
                if status in (301, 307) and region:
                    reg_url = f"https://s3.{region}.amazonaws.com/{name}"
                    try:
                        r2 = await _send_req(reg_url)
                        status = r2.status_code
                        final_url = reg_url
                    except Exception:
                        pass

                if status in (200, 403, 301, 307) or (status == 400 and region):
                    access = "Public (Exposed)" if status == 200 else "Protected (Access Denied)"
                    detected.append({
                        "name": name,
                        "provider": "AWS S3",
                        "url": final_url,
                        "status": status,
                        "access": access,
                        "region": region or "us-east-1",
                        "source": "cloud_bucket_audit",
                    })
            except Exception:
                pass

    async def check_gcp(name: str):
        url = f"https://storage.googleapis.com/{name}"
        async with sem:
            try:
                r = await _send_req(url)
                if r.status_code in (200, 403, 301, 307):
                    access = "Public (Exposed)" if r.status_code == 200 else "Protected (Access Denied)"
                    detected.append({
                        "name": name,
                        "provider": "Google Cloud Storage",
                        "url": url,
                        "status": r.status_code,
                        "access": access,
                        "source": "cloud_bucket_audit",
                    })
            except Exception:
                pass

    checked_azure = set()

    async def check_azure(name: str):
        # Azure storage accounts must be 3-24 alphanumeric lowercase chars
        clean_name = re.sub(r"[^a-z0-9]", "", name)[:24]
        if len(clean_name) < 3 or clean_name in checked_azure:
            return
        checked_azure.add(clean_name)

        url = f"https://{clean_name}.blob.core.windows.net/?comp=list"
        async with sem:
            try:
                r = await _send_req(url)
                headers = getattr(r, "headers", {}) or {}
                server_hdr = headers.get("server", "") if hasattr(headers, "get") else ""
                has_req_id = "x-ms-request-id" in headers if hasattr(headers, "__contains__") else False

                if r.status_code == 200:
                    access = "Public (Exposed)"
                elif r.status_code in (400, 403) or (
                    r.status_code == 404
                    and (has_req_id or "Microsoft-HTTPAPI" in server_hdr)
                ):
                    access = "Protected (Access Denied)"
                else:
                    return

                detected.append({
                    "name": clean_name,
                    "provider": "Azure Blob Storage",
                    "url": f"https://{clean_name}.blob.core.windows.net",
                    "status": r.status_code,
                    "access": access,
                    "source": "cloud_bucket_audit",
                })
            except Exception:
                pass

    tasks = []
    for c in candidates:
        tasks.append(check_aws(c))
        tasks.append(check_gcp(c))
        tasks.append(check_azure(c))

    await asyncio.gather(*tasks, return_exceptions=True)
    msg = f"Audited {len(candidates)} permutation candidate(s) across AWS S3, Azure Blob, and GCP; {len(detected)} detected"
    return detected, {"status": "ok", "items_returned": str(len(detected)), "message": msg}
