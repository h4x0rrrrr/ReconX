"""Filtered person-name research through configured search APIs; no fabricated results or raw dork dump."""
import asyncio, re
from urllib.parse import urlparse
import httpx
from reconx.core.config import load_config
from reconx.core.plugins import PluginContext, PluginManager, deduplicate
from reconx.plugins import BUILTIN_PLUGINS
from reconx.utils.logger import info, ok, warn


def _matches_filters(item, name, filters):
    text=(item.get("title","")+" "+item.get("snippet","")+" "+item.get("url","")).casefold()
    # Require all substantial name tokens, unless the user supplies a short name.
    tokens=[t.casefold() for t in re.findall(r"[\w'-]+",name) if len(t)>1]
    if not tokens or not all(t in text for t in tokens): return False
    for key in ("location","organization"):
        wanted=filters.get(key)
        if wanted and wanted.casefold() not in text: return False
    include=[x.casefold() for x in filters.get("keywords",[]) if x.strip()]
    exclude=[x.casefold() for x in filters.get("exclude",[]) if x.strip()]
    if include and not any(x in text for x in include): return False
    if any(x in text for x in exclude): return False
    u=item.get("url","")
    if not u.startswith(("https://","http://")): return False
    return True

def enumerate_person(full_name: str, filters=None) -> dict:
    filters=filters or {}; full_name=" ".join(full_name.split())
    if len(full_name)<3: raise ValueError("Please provide a full name (at least 3 characters).")
    query='"'+full_name+'"'
    if filters.get("location"): query += ' "'+filters["location"]+'"'
    if filters.get("organization"): query += ' "'+filters["organization"]+'"'
    if filters.get("keywords"): query += " ("+" OR ".join('"'+k+'"' for k in filters["keywords"])+")"
    cfg=load_config(); timeout=httpx.Timeout(cfg["request_timeout"])
    async def collect():
        async with httpx.AsyncClient(verify=True,timeout=timeout,headers={"User-Agent":cfg["user_agent"]},follow_redirects=True) as client:
            ctx=PluginContext(client,cfg,full_name,"person",{**filters,"query":query,"max_results":filters.get("max_results",10)})
            mgr=PluginManager([p for p in BUILTIN_PLUGINS if "person" in p.modes],cfg["concurrency"])
            return await mgr.run(ctx)
    plugin_results=asyncio.run(collect())
    raw=[]; sources=[]
    for pr in plugin_results:
        sources.append({"source":pr.source,"status":pr.status,"message":pr.message,"returned":len(pr.items)})
        raw.extend(pr.items)
    matched=[x for x in raw if _matches_filters(x,full_name,filters)]
    matched=deduplicate(matched)
    # Never expose every search-engine domain; only show filtered results with source attribution.
    results=[]
    for item in matched[:int(filters.get("max_results",20))]:
        results.append({"title":item.get("title",""),"url":item.get("url",""),"snippet":item.get("snippet",""),"sources":item.get("sources",[item.get("source","unknown")]),"status":"filtered_candidate","match_basis":"name tokens and configured filters appear in public search result"})
    import urllib.parse
    dork_links = {
        "Google Web Search": f"https://www.google.com/search?q={urllib.parse.quote_plus(query)}",
        "Google LinkedIn Dork": f"https://www.google.com/search?q={urllib.parse.quote_plus('site:linkedin.com/in/ ' + query)}",
        "Google GitHub Dork": f"https://www.google.com/search?q={urllib.parse.quote_plus('site:github.com ' + query)}",
        "Google Social Dork": f"https://www.google.com/search?q={urllib.parse.quote_plus('(site:twitter.com OR site:x.com OR site:instagram.com) ' + query)}",
    }
    if results: ok(f"Filtered public results: {len(results)}")
    else: warn("No results met all configured filters. Configure BRAVE_API_KEY, BING_API_KEY, or GOOGLE_API_KEY & GOOGLE_CSE_ID for automated live search; pre-calculated Google dorks are available below.")
    return {"name":full_name,"filters":{"location":filters.get("location"),"organization":filters.get("organization"),"keywords":filters.get("keywords",[]),"exclude":filters.get("exclude",[]),"max_results":filters.get("max_results",20)},"results":results,"result_count":len(results),"sources":sources,"query_used":query,"dork_links":dork_links,"note":"Only public search results meeting the requested name and filters are shown. These are candidates, not identity proof; manually validate before attribution."}
