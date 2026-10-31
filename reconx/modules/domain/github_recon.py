"""Passive GitHub Organization OSINT Module.

Enumerates public GitHub repositories, technology stacks, member handles,
and sensitive infrastructure repositories for the target organization.
"""
from __future__ import annotations

import os
from typing import Any

from reconx.utils.logger import debug

SENSITIVE_REPO_KEYWORDS = (
    "infra", "terraform", "k8s", "kubernetes", "ansible", "helm",
    "deploy", "docker", "config", "secret", "internal", "auth",
    "devops", "pipeline", "vault", "credentials", "backend",
)

async def enumerate_github_org(
    target: str,
    client: Any = None,
) -> tuple[dict[str, Any], str]:
    """Passively query GitHub public API for target organization metadata, repositories, and members."""
    # Deduce org candidate name from domain (e.g. "example" from "example.com" or "example-corp")
    org_candidates = [target.split(".")[0]]
    if len(target.split(".")) > 2:
        org_candidates.append(target.replace(".", "-"))

    token = os.environ.get("GITHUB_TOKEN", "").strip()
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "ReconX-OSINT/0.3.3",
    }
    if token:
        headers["Authorization"] = f"token {token}"

    intel: dict[str, Any] = {}

    for org in org_candidates:
        try:
            url = f"https://api.github.com/orgs/{org}"
            resp = await client.get(url, headers=headers, timeout=6.0)
            if resp.status_code == 200:
                data = resp.json()
                intel["org"] = data.get("login")
                intel["name"] = data.get("name")
                intel["description"] = data.get("description")
                intel["blog"] = data.get("blog")
                intel["email"] = data.get("email")
                intel["public_repos"] = data.get("public_repos", 0)
                intel["html_url"] = data.get("html_url")
                intel["created_at"] = data.get("created_at")

                # Fetch repositories
                repos_url = f"https://api.github.com/orgs/{org}/repos?sort=updated&per_page=30"
                r_resp = await client.get(repos_url, headers=headers, timeout=6.0)
                repos = []
                sensitive_repos = []
                languages = set()

                if r_resp.status_code == 200:
                    for repo in r_resp.json():
                        r_name = repo.get("name", "")
                        lang = repo.get("language")
                        if lang:
                            languages.add(lang)
                        is_sensitive = any(kw in r_name.lower() for kw in SENSITIVE_REPO_KEYWORDS)
                        repo_item = {
                            "name": r_name,
                            "url": repo.get("html_url"),
                            "language": lang,
                            "description": repo.get("description") or "",
                            "stars": repo.get("stargazers_count", 0),
                            "is_fork": repo.get("fork", False),
                            "sensitive_indicator": is_sensitive,
                        }
                        repos.append(repo_item)
                        if is_sensitive:
                            sensitive_repos.append(repo_item)

                intel["repositories"] = repos
                intel["sensitive_repos"] = sensitive_repos
                intel["languages"] = sorted(list(languages))

                # Fetch public members
                members_url = f"https://api.github.com/orgs/{org}/members?per_page=30"
                m_resp = await client.get(members_url, headers=headers, timeout=6.0)
                if m_resp.status_code == 200:
                    intel["members"] = [m.get("login") for m in m_resp.json() if m.get("login")]

                break
        except Exception as exc:
            debug(f"GitHub org enum error for {org}: {exc}")

    if not intel:
        return {}, "Skipped: No matching public GitHub organization found (or rate limited)"

    repo_cnt = len(intel.get("repositories", []))
    sens_cnt = len(intel.get("sensitive_repos", []))
    status = f"Completed ({intel.get('org')}: {repo_cnt} repos, {sens_cnt} sensitive infra repos identified)"
    return intel, status
