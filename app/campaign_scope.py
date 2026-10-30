"""Conservative matching of campaign web URLs to exact HTTP scope assets."""

import re
from urllib.parse import urlsplit


_WEB_ASSET_TYPES = {"domain", "url", "website", "web", "web application", "web_application", "wildcard"}


def validate_campaign_web_url(target_url: str, scope_assets: list[dict]) -> str:
    try:
        candidate = urlsplit(target_url)
        candidate_port = candidate.port
    except ValueError as exc:
        raise ValueError("Malformed web target URL") from exc
    hostname = (candidate.hostname or "").lower().rstrip(".")
    if (
        candidate.scheme != "https"
        or not hostname
        or candidate.username
        or candidate.password
        or candidate.query
        or candidate.fragment
        or candidate_port not in (None, 443)
    ):
        raise ValueError("Campaign web checks require an HTTPS URL without credentials, query parameters, or fragments")

    target_path = candidate.path.rstrip("/") or "/"
    for asset in scope_assets:
        asset_type = str(asset.get("type", "")).strip().casefold()
        if asset_type not in _WEB_ASSET_TYPES:
            continue
        identifier = str(asset.get("identifier", "")).strip()
        if not identifier:
            continue
        asset_url = identifier if "://" in identifier else f"https://{identifier}"
        try:
            scoped = urlsplit(asset_url)
            scoped_port = scoped.port
        except ValueError:
            continue
        scoped_hostname = (scoped.hostname or "").lower().rstrip(".")
        wildcard_match = scoped_hostname.startswith("*.") and hostname.endswith(scoped_hostname[1:]) and hostname != scoped_hostname[2:]
        exact_match = scoped_hostname == hostname
        if (
            not (wildcard_match or exact_match)
            or ("*" in scoped_hostname and not wildcard_match)
            or scoped.username
            or scoped.password
            or scoped.query
            or scoped.fragment
            or scoped_port not in (None, 443)
        ):
            continue
        scoped_path = scoped.path.rstrip("/") or "/"
        if scoped_path != "/" and target_path != scoped_path:
            continue
        return target_url

    raise ValueError("The exact HTTPS host and path are not present in this campaign's approved web scope")


def repository_matches_policy(repository_url: str, policy_text: str) -> bool:
    """Allow a repository explicitly linked in the saved, user-approved program policy."""
    candidate = urlsplit(repository_url)
    candidate_path = candidate.path.rstrip("/").removesuffix(".git").casefold()
    for owner, repo in re.findall(
        r"https?://(?:www\.)?github\.com/([A-Za-z0-9_.-]{1,100})/([A-Za-z0-9_.-]{1,100})(?:\.git)?",
        policy_text,
        flags=re.IGNORECASE,
    ):
        if candidate_path == f"/{owner}/{repo}".casefold():
            return True
    return False


def policy_forbids_remote_app_testing(policy_text: str) -> bool:
    """Conservative hard stop for explicit rules requiring a locally owned install."""
    normalized = " ".join(policy_text.casefold().split())
    phabricator_owner_rule = (
        "do not test an install of phabricator that you do not own" in normalized
        or "do not test an installation of phabricator that you do not own" in normalized
        or "do not test any other existing install" in normalized
    )
    local_copy_only = "install a local copy of phabricator" in normalized or "test a local copy of phabricator" in normalized
    return phabricator_owner_rule and local_copy_only
