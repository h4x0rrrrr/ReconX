"""Microsoft 365 / Entra ID Identity Realm & Tenant GUID discovery."""
from __future__ import annotations
import re
from typing import Any, Mapping
import httpx
from reconx.core.cache import get_cache
from reconx.utils.session import async_get_with_retry

async def discover_m365_realm(
    domain: str,
    client: httpx.AsyncClient,
    cfg: Mapping[str, Any] | None = None,
) -> tuple[dict[str, Any], dict[str, str]]:
    """Query Microsoft public realm and OpenID discovery endpoints to audit cloud identity posture."""
    clean_domain = domain.strip().lower().rstrip(".")
    cache = get_cache(enabled=(cfg or {}).get("cache_enabled", True))
    cached = cache.get("m365", clean_domain)
    if cached is not None:
        return cached, {"status": "ok", "message": "Loaded from local cache"}

    result: dict[str, Any] = {
        "domain": clean_domain,
        "is_m365": False,
        "tenant_id": None,
        "namespace_type": "Unknown",
        "is_federated": False,
        "federation_brand": None,
        "federation_auth_url": None,
        "cloud_instance": None,
        "source": "microsoft_identity_realm",
    }

    try:
        # 1. Query User Realm endpoint
        realm_url = f"https://login.microsoftonline.com/getuserrealm.srf?login=audit@{clean_domain}&xml=1"
        r_realm = await async_get_with_retry(client, realm_url, retries=2)
        if r_realm.status_code == 200:
            xml_text = r_realm.text
            ns_match = re.search(r"<NameSpaceType>(.*?)</NameSpaceType>", xml_text, re.I)
            if ns_match:
                result["namespace_type"] = ns_match.group(1).strip()
            
            fed_ns = re.search(r"<IsFederatedNS>(.*?)</IsFederatedNS>", xml_text, re.I)
            if fed_ns:
                result["is_federated"] = fed_ns.group(1).strip().lower() == "true"
            
            brand = re.search(r"<FederationBrandName>(.*?)</FederationBrandName>", xml_text, re.I)
            if brand:
                result["federation_brand"] = brand.group(1).strip()
            
            auth = re.search(r"<AuthURL>(.*?)</AuthURL>", xml_text, re.I)
            if auth:
                result["federation_auth_url"] = auth.group(1).strip()
            
            cloud = re.search(r"<CloudInstanceName>(.*?)</CloudInstanceName>", xml_text, re.I)
            if cloud:
                result["cloud_instance"] = cloud.group(1).strip()

        # 2. Query OpenID configuration for Tenant GUID
        openid_url = f"https://login.microsoftonline.com/{clean_domain}/.well-known/openid-configuration"
        r_openid = await async_get_with_retry(client, openid_url, retries=2)
        if r_openid.status_code == 200:
            m = re.search(r"login\.microsoftonline\.com/([a-f0-9\-]{36})/", r_openid.text, re.I)
            if m:
                result["tenant_id"] = m.group(1).lower()

        if result["namespace_type"] in ("Managed", "Federated") or result["tenant_id"]:
            result["is_m365"] = True

        cache.set("m365", clean_domain, result, ttl=(cfg or {}).get("cache_ttl", 86400))
        return result, {"status": "ok", "message": "M365 identity realm resolved"}
    except Exception as exc:
        return result, {"status": "error", "message": f"{type(exc).__name__}: {exc}"}
