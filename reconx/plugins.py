"""Built-in collection plugins. All providers return normalized, attributed records."""
from __future__ import annotations
import asyncio
import json
import re
import socket
from urllib.parse import quote, urlparse
from reconx.core.plugins import Plugin, PluginContext, PluginResult
from reconx.core.cache import get_cache
from reconx.utils.session import async_get_with_retry

class CrtShPlugin(Plugin):
    name = "crtsh"
    modes = {"domain"}
    rate_seconds = 0.2

    async def collect(self, ctx: PluginContext) -> PluginResult:
        d = ctx.target
        cache = get_cache(enabled=ctx.config.get("cache_enabled", True))
        cached = cache.get("crtsh", d)
        if cached is not None:
            return PluginResult(self.name, "domain", cached, "ok", "Loaded from local cache")

        try:
            r = await async_get_with_retry(ctx.client, "https://crt.sh/", retries=2, params={"q": f"%.{d}", "output": "json"})
            if r.status_code != 200:
                return PluginResult(self.name, "domain", [], "unavailable", f"HTTP {r.status_code}")
            items = []
            for row in r.json():
                for host in row.get("name_value", "").splitlines():
                    host = host.strip().lower().lstrip("*.").rstrip(".")
                    if host == d or host.endswith("." + d):
                        items.append({"host": host, "source": self.name, "evidence": "certificate transparency"})
            cache.set("crtsh", d, items, ttl=ctx.config.get("cache_ttl", 86400))
            return PluginResult(self.name, "domain", items)
        except Exception as exc:
            return PluginResult(self.name, "domain", [], "error", type(exc).__name__)

class WaybackPlugin(Plugin):
    name = "wayback"
    modes = {"domain"}
    rate_seconds = 0.4

    async def collect(self, ctx: PluginContext) -> PluginResult:
        d = ctx.target
        cache = get_cache(enabled=ctx.config.get("cache_enabled", True))
        cached = cache.get("wayback", d)
        if cached is not None:
            return PluginResult(self.name, "domain", cached, "ok", "Loaded from local cache")

        try:
            r = await async_get_with_retry(
                ctx.client,
                "https://web.archive.org/cdx/search/cdx",
                retries=2,
                params={"url": f"*.{d}/*", "output": "json", "fl": "original", "collapse": "urlkey", "limit": "5000"},
            )
            if r.status_code != 200:
                return PluginResult(self.name, "domain", [], "unavailable", f"HTTP {r.status_code}")
            rows = r.json()
            urls = []
            for row in rows[1:] if rows else []:
                if isinstance(row, list) and row and row[0].startswith(("http://", "https://")):
                    u = row[0]
                    urls.append({
                        "url": u,
                        "source": self.name,
                        "interesting": bool(re.search(r"\.(?:sql|bak|env|log|zip|xls|xlsx|config|old|swp|git)(?:\?|$)", u, re.I)),
                    })
            cache.set("wayback", d, urls, ttl=ctx.config.get("cache_ttl", 86400))
            return PluginResult(self.name, "domain", urls)
        except ValueError:
            return PluginResult(self.name, "domain", [], "error", "Unexpected CDX response")
        except Exception as exc:
            return PluginResult(self.name, "domain", [], "error", type(exc).__name__)

class DNSPlugin(Plugin):
    name = "dns"
    modes = {"domain"}
    rate_seconds = 0

    async def collect(self, ctx: PluginContext) -> PluginResult:
        try:
            import dns.resolver
        except ImportError:
            return PluginResult(self.name, "domain", [], "unavailable", "Install dnspython to enable DNS records")

        def lookup():
            result = {}
            record_types = ("A", "AAAA", "CNAME", "MX", "NS", "SOA", "TXT", "CAA", "DS", "DNSKEY", "HTTPS")
            for typ in record_types:
                try:
                    result[typ] = [str(x) for x in dns.resolver.resolve(ctx.target, typ, lifetime=4)]
                except Exception:
                    result[typ] = []
            try:
                txt = [str(x) for x in dns.resolver.resolve("_dmarc." + ctx.target, "TXT", lifetime=4)]
            except Exception:
                txt = []
            result["DMARC"] = [x for x in txt if "v=dmarc1" in x.lower()]
            result["SPF"] = [x for x in result.get("TXT", []) if "v=spf1" in x.lower()]
            return result

        records = await asyncio.to_thread(lookup)
        items = [{"value": v, "record_type": k, "source": self.name} for k, vs in records.items() for v in vs]
        return PluginResult(self.name, "domain", items, message="DNS records collected")

class BGPViewPlugin(Plugin):
    name = "bgpview"
    modes = {"domain"}
    rate_seconds = 0.25

    async def collect(self, ctx: PluginContext) -> PluginResult:
        try:
            ips = await asyncio.to_thread(lambda: sorted({x[4][0] for x in socket.getaddrinfo(ctx.target, None)}))
        except Exception:
            ips = []
        out = []
        for ip in ips[:8]:
            await asyncio.sleep(self.rate_seconds)
            try:
                r = await async_get_with_retry(ctx.client, f"https://api.bgpview.io/ip/{ip}", retries=2)
                if r.status_code != 200:
                    continue
                data = r.json().get("data", {})
                for p in data.get("prefixes", [])[:20]:
                    out.append({
                        "ip": ip,
                        "prefix": p.get("prefix"),
                        "asn": (p.get("asn") or {}).get("asn"),
                        "asn_name": (p.get("asn") or {}).get("name"),
                        "source": self.name,
                    })
            except Exception:
                continue
        return PluginResult(self.name, "domain", out)

class WhoisPlugin(Plugin):
    name = "whois"
    modes = {"domain"}
    rate_seconds = 0.5

    async def collect(self, ctx: PluginContext) -> PluginResult:
        from reconx.modules.domain.whois_intel import query_whois
        data, status = await query_whois(ctx.target, ctx.config)
        items = [data] if data else []
        return PluginResult(self.name, "domain", items, status.get("status", "ok"), status.get("message", ""))

class M365Plugin(Plugin):
    name = "m365"
    modes = {"domain"}
    rate_seconds = 0.2

    async def collect(self, ctx: PluginContext) -> PluginResult:
        from reconx.modules.domain.m365_realm import discover_m365_realm
        data, status = await discover_m365_realm(ctx.target, ctx.client, ctx.config)
        items = [data] if data else []
        return PluginResult(self.name, "domain", items, status.get("status", "ok"), status.get("message", ""))

class HibpPlugin(Plugin):
    name = "hibp"
    modes = {"username", "person", "domain"}
    rate_seconds = 1.6

    async def collect(self, ctx: PluginContext) -> PluginResult:
        from reconx.modules.breach.hibp import check_breaches
        breaches, status = await check_breaches(ctx.target, ctx.config)
        return PluginResult(self.name, ctx.mode, breaches, status.get("status", "ok"), status.get("message", ""))

class SearchPlugin(Plugin):
    """API-based search; no scraping of search result HTML and no key-less fake results."""

    def __init__(self, provider: str):
        self.provider = provider
        self.name = provider
        self.modes = {"person"}
        self.rate_seconds = 0.8

    async def collect(self, ctx: PluginContext) -> PluginResult:
        query = ctx.filters.get("query") or f'"{ctx.target}"'
        if self.provider == "brave":
            key = ctx.config.get("brave_api_key", "")
            if not key:
                return PluginResult(
                    self.name, "person", [], "not_configured",
                    "Set BRAVE_API_KEY to enable this provider",
                )
            try:
                r = await ctx.client.get(
                    "https://api.search.brave.com/res/v1/web/search",
                    headers={
                        "Accept": "application/json",
                        "Accept-Encoding": "gzip",
                        "X-Subscription-Token": key.strip(),
                    },
                    params={"q": query, "count": max(1, min(20, int(ctx.filters.get("max_results", 10))))},
                )
                if r.status_code != 200:
                    err_msg = f"HTTP {r.status_code}"
                    if r.status_code == 403:
                        err_msg += " (Forbidden: check that Free Plan subscription is active in dashboard)"
                    return PluginResult(self.name, "person", [], "unavailable", err_msg)
                rows = r.json().get("web", {}).get("results", [])
                items = [{"title": x.get("title", ""), "url": x.get("url", ""), "snippet": x.get("description", ""), "source": self.name} for x in rows]
                return PluginResult(self.name, "person", items)
            except Exception as exc:
                return PluginResult(self.name, "person", [], "error", type(exc).__name__)

        elif self.provider == "bing":
            key = ctx.config.get("bing_api_key", "")
            if not key:
                return PluginResult(
                    self.name, "person", [], "not_configured",
                    "Set BING_API_KEY to enable this provider",
                )
            try:
                r = await ctx.client.get(
                    "https://api.bing.microsoft.com/v7.0/search",
                    headers={"Ocp-Apim-Subscription-Key": key},
                    params={"q": query, "count": max(1, min(20, int(ctx.filters.get("max_results", 10))))},
                )
                if r.status_code != 200:
                    return PluginResult(self.name, "person", [], "unavailable", f"HTTP {r.status_code}")
                rows = r.json().get("webPages", {}).get("value", [])
                items = [{"title": x.get("name", ""), "url": x.get("url", ""), "snippet": x.get("snippet", ""), "source": self.name} for x in rows]
                return PluginResult(self.name, "person", items)
            except Exception as exc:
                return PluginResult(self.name, "person", [], "error", type(exc).__name__)

        elif self.provider == "google":
            key = ctx.config.get("google_api_key", "")
            cse_id = ctx.config.get("google_cse_id", "")
            if not key or not cse_id:
                return PluginResult(
                    self.name, "person", [], "not_configured",
                    "Set GOOGLE_API_KEY and GOOGLE_CSE_ID to enable Google search",
                )
            try:
                r = await ctx.client.get(
                    "https://customsearch.googleapis.com/customsearch/v1",
                    params={
                        "key": key,
                        "cx": cse_id,
                        "q": query,
                        "num": max(1, min(10, int(ctx.filters.get("max_results", 10)))),
                    },
                )
                if r.status_code != 200:
                    return PluginResult(self.name, "person", [], "unavailable", f"HTTP {r.status_code}")
                rows = r.json().get("items", [])
                items = [{"title": x.get("title", ""), "url": x.get("link", ""), "snippet": x.get("snippet", ""), "source": self.name} for x in rows]
                return PluginResult(self.name, "person", items)
            except Exception as exc:
                return PluginResult(self.name, "person", [], "error", type(exc).__name__)

        return PluginResult(self.name, "person", [], "not_configured", "Unknown search provider")

class SerperPlugin(Plugin):
    """Real Google Search API via Serper.dev (2,500 free queries on signup, no credit card required)."""
    name = "serper"
    modes = {"person"}
    rate_seconds = 0.5

    async def collect(self, ctx: PluginContext) -> PluginResult:
        query = ctx.filters.get("query") or f'"{ctx.target}"'
        key = ctx.config.get("serper_api_key", "")
        if not key:
            return PluginResult(self.name, "person", [], "not_configured", "Set SERPER_API_KEY to enable Google search via Serper (free 2,500 queries at serper.dev)")
        try:
            r = await ctx.client.post(
                "https://google.serper.dev/search",
                headers={"X-API-KEY": key, "Content-Type": "application/json"},
                json={"q": query, "num": max(1, min(20, int(ctx.filters.get("max_results", 10))))},
            )
            if r.status_code != 200:
                return PluginResult(self.name, "person", [], "unavailable", f"HTTP {r.status_code}")
            rows = r.json().get("organic", [])
            items = [{"title": x.get("title", ""), "url": x.get("link", ""), "snippet": x.get("snippet", ""), "source": "google"} for x in rows]
            return PluginResult(self.name, "person", items)
        except Exception as exc:
            return PluginResult(self.name, "person", [], "error", type(exc).__name__)

class GitHubCodePlugin(Plugin):
    """Authenticated public GitHub code search; no secret values are emitted."""
    name = "github_code"
    modes = {"domain"}
    rate_seconds = 1.0

    async def collect(self, ctx: PluginContext) -> PluginResult:
        token = ctx.config.get("github_token", "")
        if not token:
            return PluginResult(self.name, "domain", [], "not_configured", "Set GITHUB_TOKEN to enable public code-search integration")
        query = f'"{ctx.target}"'
        try:
            r = await ctx.client.get(
                "https://api.github.com/search/code",
                headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"},
                params={"q": query, "per_page": 30},
            )
            if r.status_code != 200:
                return PluginResult(self.name, "domain", [], "unavailable", f"HTTP {r.status_code}")
            items = []
            for x in r.json().get("items", []):
                items.append({
                    "url": x.get("html_url", ""),
                    "repository": (x.get("repository") or {}).get("full_name", ""),
                    "path": x.get("path", ""),
                    "source": self.name,
                    "evidence": "public GitHub code search reference; content not downloaded",
                })
            return PluginResult(self.name, "domain", items)
        except Exception as exc:
            return PluginResult(self.name, "domain", [], "error", type(exc).__name__)

class ShodanPlugin(Plugin):
    name = "shodan"
    modes = {"domain"}
    rate_seconds = 1.0

    async def collect(self, ctx: PluginContext) -> PluginResult:
        key = ctx.config.get("shodan_api_key", "")
        if not key:
            return PluginResult(self.name, "domain", [], "not_configured", "Set SHODAN_API_KEY to enable Shodan search")
        try:
            r = await ctx.client.get("https://api.shodan.io/shodan/host/search", params={"key": key, "query": f"hostname:{ctx.target}", "page": 1})
            if r.status_code == 200:
                items = []
                for x in r.json().get("matches", [])[:100]:
                    items.append({
                        "ip": x.get("ip_str"),
                        "port": x.get("port"),
                        "service": x.get("product") or f"port-{x.get('port')}",
                        "hostnames": x.get("hostnames", []),
                        "product": x.get("product", ""),
                        "org": x.get("org", ""),
                        "source": self.name,
                        "evidence": "Shodan indexed service metadata; verify current exposure",
                    })
                return PluginResult(self.name, "domain", items)

            # Fallback to direct host IP lookup (fully supported on free Shodan plans!)
            import socket
            try:
                ip = await asyncio.to_thread(socket.gethostbyname, ctx.target)
                r_host = await ctx.client.get(f"https://api.shodan.io/shodan/host/{ip}", params={"key": key})
                if r_host.status_code == 200:
                    h_data = r_host.json()
                    ports = h_data.get("ports", [])
                    known_ports = {80: "http", 443: "https", 21: "ftp", 22: "ssh", 25: "smtp", 53: "dns", 110: "pop3", 143: "imap", 3306: "mysql", 5432: "postgresql", 6379: "redis", 8080: "http-proxy", 8443: "https-alt"}
                    items = []
                    for p in ports[:30]:
                        items.append({
                            "ip": ip,
                            "port": p,
                            "service": known_ports.get(p, f"port-{p}"),
                            "hostnames": h_data.get("hostnames", []),
                            "product": h_data.get("os", ""),
                            "org": h_data.get("org", ""),
                            "source": self.name,
                            "evidence": f"Shodan direct IP intelligence ({len(ports)} open ports observed)",
                        })
                    return PluginResult(self.name, "domain", items)
            except Exception:
                pass

            return PluginResult(self.name, "domain", [], "unavailable", f"HTTP {r.status_code}")
        except Exception as exc:
            return PluginResult(self.name, "domain", [], "error", type(exc).__name__)

class CensysPlugin(Plugin):
    name = "censys"
    modes = {"domain"}
    rate_seconds = 1.0

    async def collect(self, ctx: PluginContext) -> PluginResult:
        token = ctx.config.get("censys_token", "")
        ident = ctx.config.get("censys_api_id", "")
        secret = ctx.config.get("censys_api_secret", "")

        if not token and not (ident and secret):
            return PluginResult(self.name, "domain", [], "not_configured", "Set CENSYS_TOKEN (Personal Access Token) to enable Censys")

        try:
            # 1. Censys Platform API (v3) with Personal Access Token
            if token:
                import socket
                try:
                    ip = await asyncio.to_thread(socket.gethostbyname, ctx.target)
                except Exception:
                    ip = None
                if not ip:
                    return PluginResult(self.name, "domain", [], "ok", "Target did not resolve to IP for Censys asset lookup")

                r = await ctx.client.get(
                    f"https://api.platform.censys.io/v3/global/asset/host/{ip}",
                    headers={"Authorization": f"Bearer {token}"},
                )
                if r.status_code != 200:
                    return PluginResult(self.name, "domain", [], "unavailable", f"HTTP {r.status_code}")
                res_data = r.json().get("result", {}).get("resource", {})
                services = res_data.get("services", [])
                as_info = res_data.get("autonomous_system", {})
                as_name = as_info.get("name") or as_info.get("description", "") if isinstance(as_info, dict) else ""
                items = []
                for s in services[:30]:
                    software = s.get("software", [{}])
                    prod = software[0].get("product", "") if software and isinstance(software, list) and isinstance(software[0], dict) else ""
                    items.append({
                        "ip": ip,
                        "port": s.get("port"),
                        "service": s.get("service_name") or s.get("transport_protocol"),
                        "product": prod,
                        "org": as_name,
                        "location": res_data.get("location", {}).get("country", ""),
                        "source": self.name,
                        "evidence": f"Censys Platform v3 asset intelligence ({len(services)} services observed)",
                    })
                return PluginResult(self.name, "domain", items)

            # 2. Legacy fallback
            r = await ctx.client.get("https://search.censys.io/api/v2/hosts/search", auth=(ident, secret), params={"q": f"{ctx.target}", "per_page": 25})
            if r.status_code != 200:
                return PluginResult(self.name, "domain", [], "unavailable", f"HTTP {r.status_code}")
            items = []
            for x in r.json().get("result", {}).get("hits", []):
                for s in x.get("services", []):
                    items.append({
                        "ip": x.get("ip"),
                        "port": s.get("port"),
                        "service": s.get("service_name") or s.get("transport_protocol"),
                        "product": "",
                        "org": x.get("autonomous_system", {}).get("name", "") if isinstance(x.get("autonomous_system"), dict) else "",
                        "location": "",
                        "source": self.name,
                        "evidence": "Censys indexed host metadata",
                    })
            return PluginResult(self.name, "domain", items)
        except Exception as exc:
            return PluginResult(self.name, "domain", [], "error", type(exc).__name__)

class URLScanPlugin(Plugin):
    name = "urlscan"
    modes = {"domain"}
    rate_seconds = 1.0

    async def collect(self, ctx: PluginContext) -> PluginResult:
        try:
            r = await ctx.client.get("https://urlscan.io/api/v1/search/", params={"q": f"domain:{ctx.target}", "size": 50})
            if r.status_code != 200:
                return PluginResult(self.name, "domain", [], "unavailable", f"HTTP {r.status_code}")
            items = []
            for x in r.json().get("results", []):
                page = x.get("page", {})
                items.append({
                    "url": page.get("url", ""),
                    "domain": page.get("domain", ""),
                    "ip": page.get("ip", ""),
                    "title": page.get("title", ""),
                    "scan_id": x.get("_id"),
                    "source": self.name,
                    "evidence": "public URLScan record; historical snapshot may be stale",
                })
            return PluginResult(self.name, "domain", items)
        except Exception as exc:
            return PluginResult(self.name, "domain", [], "error", type(exc).__name__)

BUILTIN_PLUGINS = [
    CrtShPlugin(),
    WaybackPlugin(),
    DNSPlugin(),
    BGPViewPlugin(),
    WhoisPlugin(),
    M365Plugin(),
    HibpPlugin(),
    SearchPlugin("brave"),
    SearchPlugin("bing"),
    SearchPlugin("google"),
    SerperPlugin(),
    GitHubCodePlugin(),
    ShodanPlugin(),
    CensysPlugin(),
    URLScanPlugin(),
]
