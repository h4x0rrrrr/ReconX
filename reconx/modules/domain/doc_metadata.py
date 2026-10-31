"""Public document metadata harvester and username convention analyzer.

Discovers public PDF/DOCX/XLSX documents from search APIs and Wayback archives,
extracts author/creator metadata via exiftool (or pure-Python fallback),
and analyzes author patterns to infer corporate username conventions.
"""
from __future__ import annotations
import asyncio
import io
import json
import os
import re
import shutil
import subprocess
import tempfile
import zipfile
import xml.etree.ElementTree as ET
from typing import Any
import httpx
from reconx.utils.session import create_async_client, async_get_with_retry

DOC_EXTENSIONS = (".pdf", ".docx", ".xlsx", ".pptx", ".doc", ".xls")

def _parse_pdf_metadata_native(content: bytes) -> dict[str, str]:
    meta: dict[str, str] = {}
    try:
        # Search for /Author, /Creator, /Producer, /CreationDate in PDF info dictionary
        text_sample = content[:10000].decode("latin1", errors="ignore") + content[-20000:].decode("latin1", errors="ignore")
        for field in ("Author", "Creator", "Producer", "Title", "Subject"):
            match = re.search(rf"/{field}\s*\(([^\)]{{1,120}})\)", text_sample)
            if match:
                meta[field.lower()] = match.group(1).strip()
    except Exception:
        pass
    return meta

def _parse_docx_metadata_native(content: bytes) -> dict[str, str]:
    meta: dict[str, str] = {}
    try:
        with zipfile.ZipFile(io.BytesIO(content)) as zf:
            if "docProps/core.xml" in zf.namelist():
                xml_data = zf.read("docProps/core.xml")
                root = ET.fromstring(xml_data)
                namespaces = {
                    "dc": "http://purl.org/dc/elements/1.1/",
                    "cp": "http://schemas.openxmlformats.org/package/2006/metadata/core-properties",
                }
                creator = root.find("dc:creator", namespaces)
                if creator is not None and creator.text:
                    meta["author"] = creator.text.strip()
                last_mod = root.find("cp:lastModifiedBy", namespaces)
                if last_mod is not None and last_mod.text:
                    meta["last_modified_by"] = last_mod.text.strip()
                title = root.find("dc:title", namespaces)
                if title is not None and title.text:
                    meta["title"] = title.text.strip()
    except Exception:
        pass
    return meta

def _extract_with_exiftool(file_path: str) -> dict[str, str]:
    if not shutil.which("exiftool"):
        return {}
    try:
        proc = subprocess.run(
            ["exiftool", "-j", "-Author", "-Creator", "-Producer", "-LastModifiedBy", "-Title", "-CreateDate", file_path],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if proc.returncode == 0 and proc.stdout:
            data = json.loads(proc.stdout)
            if data and isinstance(data, list):
                item = data[0]
                return {
                    "author": str(item.get("Author", "")).strip(),
                    "creator": str(item.get("Creator", "")).strip(),
                    "producer": str(item.get("Producer", "")).strip(),
                    "last_modified_by": str(item.get("LastModifiedBy", "")).strip(),
                    "title": str(item.get("Title", "")).strip(),
                    "create_date": str(item.get("CreateDate", "")).strip(),
                }
    except Exception:
        pass
    return {}

def infer_username_conventions(authors: list[str]) -> list[str]:
    """Analyzes a list of author names to infer email/username naming conventions."""
    conventions = set()
    for raw in authors:
        cleaned = re.sub(r"[^\w\s.-]", "", raw).strip()
        if not cleaned or len(cleaned) < 3 or len(cleaned) > 40:
            continue
        parts = re.split(r"[\s._-]+", cleaned)
        if len(parts) == 2:
            first, last = parts[0].lower(), parts[1].lower()
            if first.isalpha() and last.isalpha():
                conventions.add(f"first.last (e.g. {first}.{last})")
                conventions.add(f"flast (e.g. {first[0]}{last})")
                conventions.add(f"firstl (e.g. {first}{last[0]})")
        elif len(parts) == 1 and not parts[0].isdigit():
            token = parts[0].lower()
            if "." in raw:
                conventions.add("dot-separated usernames (e.g. user.name)")
            elif len(token) <= 8 and token.isalnum():
                conventions.add(f"short-token identifier (e.g. {token})")

    return sorted(list(conventions))

async def harvest_document_metadata(
    domain: str,
    candidate_urls: list[str],
    cfg: dict[str, Any],
    max_docs: int = 8,
) -> tuple[list[dict[str, Any]], list[str], dict[str, Any]]:
    """Download public documents from candidate URLs, extract metadata, and infer username conventions."""
    doc_urls = [u for u in candidate_urls if any(u.lower().split("?")[0].endswith(ext) for ext in DOC_EXTENSIONS)]
    doc_urls = list(dict.fromkeys(doc_urls))[:max_docs]

    if not doc_urls:
        return [], [], {"status": "clean", "message": "No public document URLs found to harvest"}

    harvested: list[dict[str, Any]] = []
    authors: list[str] = []
    sem = asyncio.Semaphore(4)

    async with create_async_client(cfg, timeout=8.0) as client:
        async def process_doc(url: str):
            async with sem:
                try:
                    resp = await async_get_with_retry(client, url, retries=1)
                    if resp.status_code != 200:
                        return
                    content = resp.content
                    if len(content) > 6_000_000 or len(content) < 100:
                        return  # Skip overly large files or empty responses

                    filename = url.split("?")[0].split("/")[-1] or "document"
                    ext = os.path.splitext(filename)[1].lower()

                    meta: dict[str, str] = {}
                    # Try exiftool first if available
                    if shutil.which("exiftool"):
                        with tempfile.NamedTemporaryFile(suffix=ext, delete=False) as tmp:
                            tmp.write(content)
                            tmp_path = tmp.name
                        try:
                            meta = _extract_with_exiftool(tmp_path)
                        finally:
                            if os.path.exists(tmp_path):
                                os.remove(tmp_path)

                    # Pure Python fallback
                    if not meta.get("author"):
                        if ext == ".pdf":
                            meta.update(_parse_pdf_metadata_native(content))
                        elif ext in (".docx", ".xlsx", ".pptx"):
                            meta.update(_parse_docx_metadata_native(content))

                    author = meta.get("author") or meta.get("creator") or meta.get("last_modified_by") or ""
                    if author:
                        authors.append(author)

                    harvested.append({
                        "url": url,
                        "filename": filename,
                        "author": author,
                        "creator": meta.get("creator", ""),
                        "producer": meta.get("producer", ""),
                        "last_modified_by": meta.get("last_modified_by", ""),
                        "title": meta.get("title", ""),
                        "source": "document_metadata",
                    })
                except Exception:
                    pass

        await asyncio.gather(*(process_doc(u) for u in doc_urls))

    conventions = infer_username_conventions(authors)
    status = {
        "status": "ok",
        "message": f"Harvested metadata from {len(harvested)} document(s); {len(authors)} author(s) extracted",
        "documents_analyzed": len(harvested),
    }
    return harvested, conventions, status
