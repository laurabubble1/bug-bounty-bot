"""Read-only imports from official bounty platform APIs; never scans discovered assets."""

import asyncio
import json
from typing import Any
from urllib.parse import urljoin, urlsplit

import httpx

from app.core.config import settings

_TIMEOUT = httpx.Timeout(12.0)
_MAX_BODY_BYTES = 2_000_000


async def _json_response(
    client: httpx.AsyncClient,
    url: str,
    *,
    params: dict[str, str] | None = None,
) -> dict[str, Any]:
    async with client.stream("GET", url, params=params) as response:
        response.raise_for_status()
        data = bytearray()
        async for chunk in response.aiter_bytes():
            if len(data) + len(chunk) > _MAX_BODY_BYTES:
                raise ValueError("Platform response exceeded the 2 MB safety limit")
            data.extend(chunk)
        parsed = json.loads(data)
        if not isinstance(parsed, dict):
            raise ValueError("Platform returned an unexpected response")
        return parsed


def _matches(search: str, *parts: str) -> bool:
    return not search or search.casefold() in " ".join(parts).casefold()


async def discover_hackerone(search: str = "") -> dict[str, Any]:
    result: dict[str, Any] = {
        "provider": "HackerOne",
        "configured": bool(settings.hackerone_api_username and settings.hackerone_api_token),
        "ok": False,
        "programs": [],
    }
    if not result["configured"]:
        return result

    auth = (settings.hackerone_api_username, settings.hackerone_api_token)
    headers = {"Accept": "application/json", "User-Agent": "Scopeguard-Program-Discovery/1.0"}
    base = "https://api.hackerone.com/v1/hackers"
    try:
        async with httpx.AsyncClient(
            timeout=_TIMEOUT, follow_redirects=False, verify=True, trust_env=False, auth=auth, headers=headers
        ) as client:
            payload = await _json_response(
                client,
                f"{base}/programs",
                params={"page[number]": "1", "page[size]": "100"},
            )
            programs = payload.get("data", [])
            eligible: list[dict[str, Any]] = []
            for program in programs if isinstance(programs, list) else []:
                attrs = program.get("attributes", {})
                handle = str(attrs.get("handle", ""))
                name = str(attrs.get("name") or handle)
                if (
                    attrs.get("state") != "public_mode"
                    or attrs.get("submission_state") != "open"
                    or attrs.get("offers_bounties") is not True
                ):
                    continue
                eligible.append({"handle": handle, "name": name, "attrs": attrs})
            named_matches = [
                item for item in eligible
                if _matches(search, item["name"], item["handle"], str(item["attrs"].get("policy", "")))
            ]
            chosen = (named_matches or eligible)[:20]

            semaphore = asyncio.Semaphore(3)

            async def fetch_program(item: dict[str, Any]) -> dict[str, Any]:
                async with semaphore:
                    scopes_url = f"{base}/programs/{item['handle']}/structured_scopes"
                    next_url: str | None = scopes_url
                    params: dict[str, str] | None = {"page[size]": "100"}
                    scope_data: list[dict[str, Any]] = []
                    scope_complete = True
                    for _ in range(5):
                        if next_url is None:
                            break
                        scopes = await _json_response(client, next_url, params=params)
                        params = None
                        page_data = scopes.get("data", [])
                        if isinstance(page_data, list):
                            scope_data.extend(item for item in page_data if isinstance(item, dict))
                        link = scopes.get("links", {}).get("next")
                        if not link:
                            next_url = None
                            break
                        candidate_url = urljoin(scopes_url, str(link))
                        parsed_next = urlsplit(candidate_url)
                        if (
                            parsed_next.scheme != "https"
                            or parsed_next.hostname != "api.hackerone.com"
                            or parsed_next.port not in (None, 443)
                            or parsed_next.username
                            or parsed_next.password
                            or parsed_next.fragment
                            or parsed_next.path != urlsplit(scopes_url).path
                        ):
                            raise ValueError("HackerOne returned an unexpected scope pagination link")
                        next_url = candidate_url
                    if next_url is not None:
                        scope_complete = False
                assets = []
                for scope in scope_data:
                    fields = scope.get("attributes", {})
                    if fields.get("eligible_for_submission") is not True:
                        continue
                    assets.append({
                        "identifier": str(fields.get("asset_identifier", "")),
                        "type": str(fields.get("asset_type", "unknown")),
                        "eligible_for_bounty": fields.get("eligible_for_bounty") is True,
                        "eligible_for_submission": True,
                        "instruction": str(fields.get("instruction", ""))[:500],
                    })
                attrs = item["attrs"]
                return {
                    "provider": "HackerOne",
                    "name": item["name"],
                    "platform_url": f"https://hackerone.com/{item['handle']}",
                    "policy_text": str(attrs.get("policy") or "")[:30000],
                    "status": "Public and accepting submissions (API snapshot)",
                    "offers_bounties": True,
                    "open_scope": attrs.get("open_scope") is True,
                    "assets": assets[:100],
                    "assets_complete_in_response": scope_complete and len(assets) <= 100,
                    "checked_at": "Current API response",
                }

            gathered = await asyncio.gather(*(fetch_program(item) for item in chosen), return_exceptions=True)
            loaded = [item for item in gathered if isinstance(item, dict)]
            result["programs"] = [
                item for item in loaded
                if _matches(search, item["name"], *(asset["identifier"] for asset in item["assets"]))
            ]
            result["program_list_limited_to_first_100"] = bool(payload.get("links", {}).get("next"))
            if any(isinstance(item, Exception) for item in gathered):
                result["warning"] = "Some program scope details could not be loaded. Open the official brief before relying on this list."
            result["ok"] = True
    except (httpx.HTTPError, ValueError, KeyError, TypeError) as exc:
        result["error"] = f"HackerOne discovery failed ({type(exc).__name__}). Check the API credentials and retry."
    return result


async def discover_bugcrowd(search: str = "") -> dict[str, Any]:
    result: dict[str, Any] = {
        "provider": "Bugcrowd",
        "configured": bool(settings.bugcrowd_api_username and settings.bugcrowd_api_token),
        "ok": False,
        "programs": [],
    }
    if not result["configured"]:
        return result

    headers = {
        "Accept": "application/vnd.bugcrowd+json",
        "Authorization": f"Token {settings.bugcrowd_api_username}:{settings.bugcrowd_api_token}",
        "User-Agent": "Scopeguard-Program-Discovery/1.0",
    }
    params = {
        "filter[participation]": "public",
        "page[limit]": "100",
        "page[offset]": "0",
        "include": "current_brief.target_groups.targets,current_brief.target_groups.reward_range",
        "fields[program]": "code,name,current_brief",
        "fields[program_brief]": "target_groups",
        "fields[target_group]": "name,targets,reward_range",
        "fields[target]": "name",
        "fields[reward_range]": "p1_max_cents,p2_max_cents,p3_max_cents,p4_max_cents",
    }
    try:
        async with httpx.AsyncClient(
            timeout=_TIMEOUT, follow_redirects=False, verify=True, trust_env=False, headers=headers
        ) as client:
            payload = await _json_response(client, "https://api.bugcrowd.com/programs", params=params)
        included = payload.get("included", [])
        included_by_id = {
            (item.get("type"), item.get("id")): item
            for item in included if isinstance(item, dict)
        } if isinstance(included, list) else {}
        records = payload.get("data", [])
        for program in records if isinstance(records, list) else []:
            attrs = program.get("attributes", {})
            code = str(attrs.get("code", ""))
            name = str(attrs.get("name") or code)
            if not _matches(search, name, code):
                continue
            brief_rel = program.get("relationships", {}).get("current_brief", {}).get("data") or {}
            brief = included_by_id.get((brief_rel.get("type", "program_brief"), brief_rel.get("id")), {})
            group_rels = brief.get("relationships", {}).get("target_groups", {}).get("data", [])
            assets: list[dict[str, Any]] = []
            max_reward_cents = 0
            assets_complete = True
            for group_rel in group_rels if isinstance(group_rels, list) else []:
                group = included_by_id.get((group_rel.get("type", "target_group"), group_rel.get("id")), {})
                group_attrs = group.get("attributes", {})
                target_rels = group.get("relationships", {}).get("targets", {}).get("data", [])
                target_meta = group.get("relationships", {}).get("targets", {}).get("links", {}).get("related", {}).get("meta", {})
                if isinstance(target_meta.get("total_hits"), int) and target_meta["total_hits"] > len(target_rels):
                    assets_complete = False
                for target_rel in target_rels if isinstance(target_rels, list) else []:
                    target = included_by_id.get((target_rel.get("type", "target"), target_rel.get("id")), {})
                    target_name = str(target.get("attributes", {}).get("name", ""))
                    if _matches(search, name, code, target_name, str(group_attrs.get("name", ""))):
                        assets.append({
                            "identifier": target_name,
                            "type": "Program asset (verify in brief)",
                            "eligible_for_bounty": None,
                            "eligible_for_submission": None,
                            "instruction": "Confirm this asset and its testing rules in the current program brief.",
                        })
                reward_rel = group.get("relationships", {}).get("reward_range", {}).get("data") or {}
                reward = included_by_id.get((reward_rel.get("type", "reward_range"), reward_rel.get("id")), {})
                reward_attrs = reward.get("attributes", {})
                for key in ("p1_max_cents", "p2_max_cents", "p3_max_cents", "p4_max_cents"):
                    value = reward_attrs.get(key)
                    if isinstance(value, (int, float)):
                        max_reward_cents = max(max_reward_cents, int(value))
            if search and not assets and not _matches(search, name, code):
                continue
            result["programs"].append({
                "provider": "Bugcrowd",
                "name": name,
                "platform_url": f"https://bugcrowd.com/engagements/{code}" if code else "https://bugcrowd.com/engagements",
                "status": "Public listing snapshot; confirm current participation status",
                "offers_bounties": max_reward_cents > 0,
                "open_scope": None,
                "maximum_reward_cents": max_reward_cents,
                "assets": assets[:100],
                "assets_complete_in_response": assets_complete,
                "checked_at": "Current API response",
            })
        result["program_list_limited_to_first_100"] = bool(payload.get("links", {}).get("next"))
        result["ok"] = True
    except (httpx.HTTPError, ValueError, KeyError, TypeError) as exc:
        result["error"] = f"Bugcrowd discovery failed ({type(exc).__name__}). Check the API credentials and retry."
    return result


async def discover_opportunities(search: str = "") -> list[dict[str, Any]]:
    """HackerOne-only opportunity lookup; Bugcrowd is disabled until account access is resolved."""
    return [await discover_hackerone(search)]
