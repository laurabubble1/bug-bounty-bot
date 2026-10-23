import asyncio
import hashlib
import re
import uuid
from urllib.parse import urlsplit, urlunsplit

import httpx

from app.core.config import settings
from app.core.security import validate_target_url
from app.plugins.base import BaseScannerPlugin, LogCallback, PluginFinding

_PARAM_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


class ParameterReflectionPlugin(BaseScannerPlugin):
    key = "parameter-reflection"
    description = "Checks declared query parameters using one inert marker per parameter."

    async def scan(self, *, base_url: str, options: dict, log: LogCallback) -> list[PluginFinding]:
        validate_target_url(base_url)
        parameters = options.get("parameters", [])
        if not isinstance(parameters, list) or not 1 <= len(parameters) <= settings.max_requests_per_job:
            raise ValueError(f"Provide between 1 and {settings.max_requests_per_job} query parameter names")
        if any(not isinstance(name, str) or not _PARAM_RE.fullmatch(name) for name in parameters):
            raise ValueError("Parameter names must match [A-Za-z0-9_.-], max 64 characters")
        if urlsplit(base_url).query:
            raise ValueError("Target URL must not contain a query string")

        findings: list[PluginFinding] = []
        timeout = httpx.Timeout(settings.request_timeout_seconds)
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False, verify=True, trust_env=False) as client:
            for name in dict.fromkeys(parameters):
                marker = f"audit-check-{uuid.uuid4().hex[:12]}"
                response_text = ""
                response_status = "no response"
                for attempt in range(2):  # One bounded retry; no retry on HTTP status codes.
                    await asyncio.sleep(settings.request_interval_seconds)
                    try:
                        async with client.stream("GET", base_url, params={name: marker}, headers={"User-Agent": "Authorized-Audit-Check/1.0"}) as response:
                            response_status = str(response.status_code)
                            chunks: list[bytes] = []
                            size = 0
                            async for chunk in response.aiter_bytes():
                                remaining = 65536 - size
                                if remaining <= 0:
                                    break
                                chunks.append(chunk[:remaining])
                                size += min(len(chunk), remaining)
                            response_text = b"".join(chunks).decode(response.encoding or "utf-8", errors="replace")
                        break
                    except (httpx.TimeoutException, httpx.ConnectError) as exc:
                        if attempt == 0:
                            await log("WARNING", f"Transient network error for parameter '{name}'; retrying once")
                        else:
                            await log("ERROR", f"Request failed for parameter '{name}' ({type(exc).__name__})")
                endpoint = urlunsplit((*urlsplit(base_url)[:3], "", ""))
                await log("INFO", f"Checked parameter '{name}' (HTTP {response_status})")
                if marker in response_text:
                    fingerprint = hashlib.sha256(f"{endpoint}|{name}|reflected".encode()).hexdigest()
                    findings.append(PluginFinding(
                        title=f"Input marker reflected in response ({name})",
                        severity="info",
                        fingerprint=fingerprint,
                        evidence="An inert unique marker appeared in the first 64 KiB of the response; manual review required.",
                        endpoint_url=endpoint,
                    ))
        return findings
