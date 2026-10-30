import hashlib
from urllib.parse import urlsplit, urlunsplit

import httpx

from app.core.config import settings
from app.core.security import validate_target_url
from app.plugins.base import BaseScannerPlugin, LogCallback, PluginFinding


class SecurityHeadersPlugin(BaseScannerPlugin):
    key = "security-headers"
    description = "Reviews browser security headers, cookie flags, and CORS behavior using one GET request."

    CORS_PROBE_ORIGIN = "https://scopeguard.invalid"

    REQUIRED_HEADERS = {
        "strict-transport-security": "HTTP Strict Transport Security",
        "content-security-policy": "Content Security Policy",
        "x-content-type-options": "X-Content-Type-Options",
        "referrer-policy": "Referrer Policy",
        "permissions-policy": "Permissions Policy",
    }

    async def scan(self, *, base_url: str, options: dict, log: LogCallback) -> list[PluginFinding]:
        validate_target_url(
            base_url,
            additional_allowed_hosts=set(options.get("approved_hosts", [])),
        )
        endpoint = urlunsplit((*urlsplit(base_url)[:3], "", ""))
        timeout = httpx.Timeout(settings.request_timeout_seconds)
        await log("INFO", "Checking common response security headers (one GET request)")
        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=False,
            verify=True,
            trust_env=False,
        ) as client:
            async with client.stream(
                "GET",
                base_url,
                headers={
                    "User-Agent": "Authorized-Audit-Check/1.0",
                    "Origin": self.CORS_PROBE_ORIGIN,
                },
            ) as response:
                status_code = response.status_code
                response_headers = response.headers

        findings: list[PluginFinding] = []
        for header, label in self.REQUIRED_HEADERS.items():
            if header == "strict-transport-security" and urlsplit(base_url).scheme != "https":
                continue
            if header not in response_headers:
                fingerprint = hashlib.sha256(f"{endpoint}|missing-header|{header}".encode()).hexdigest()
                findings.append(PluginFinding(
                    title=f"Response is missing {label}",
                    severity="low",
                    fingerprint=fingerprint,
                    evidence=(
                        f"The response did not include {header}. Review whether this header is appropriate "
                        "for this application; absence alone does not prove an exploitable vulnerability."
                    ),
                    endpoint_url=endpoint,
                ))

        # Cookie values are deliberately not read or stored; only attributes are reviewed.
        for cookie in response_headers.get_list("set-cookie"):
            parts = [part.strip().lower() for part in cookie.split(";")]
            cookie_name = cookie.split("=", 1)[0].strip() or "unnamed cookie"
            flags = {part.split("=", 1)[0] for part in parts[1:]}
            if urlsplit(base_url).scheme == "https" and "secure" not in flags:
                findings.append(PluginFinding(
                    title=f"Cookie may be missing Secure ({cookie_name})",
                    severity="low",
                    fingerprint=hashlib.sha256(f"{endpoint}|cookie|{cookie_name}|secure".encode()).hexdigest(),
                    evidence="A Set-Cookie response lacked the Secure attribute on an HTTPS request. Review whether the cookie contains sensitive state.",
                    endpoint_url=endpoint,
                ))
            if "httponly" not in flags:
                findings.append(PluginFinding(
                    title=f"Cookie may be accessible to scripts ({cookie_name})",
                    severity="low",
                    fingerprint=hashlib.sha256(f"{endpoint}|cookie|{cookie_name}|httponly".encode()).hexdigest(),
                    evidence="A Set-Cookie response lacked HttpOnly. Review whether client-side code needs access; this observation alone does not establish impact.",
                    endpoint_url=endpoint,
                ))
            if not any(part.startswith("samesite=") for part in parts[1:]):
                findings.append(PluginFinding(
                    title=f"Cookie may be missing SameSite ({cookie_name})",
                    severity="low",
                    fingerprint=hashlib.sha256(f"{endpoint}|cookie|{cookie_name}|samesite".encode()).hexdigest(),
                    evidence="A Set-Cookie response lacked an explicit SameSite attribute. Review the application's cross-site request requirements.",
                    endpoint_url=endpoint,
                ))

        allowed_origin = response_headers.get("access-control-allow-origin", "").strip()
        if allowed_origin == "*" or allowed_origin == self.CORS_PROBE_ORIGIN:
            credentials = response_headers.get("access-control-allow-credentials", "").strip().lower()
            policy = "wildcard origin" if allowed_origin == "*" else "reflected arbitrary origin"
            findings.append(PluginFinding(
                title=f"CORS allows the probe origin ({policy})",
                severity="info",
                fingerprint=hashlib.sha256(f"{endpoint}|cors|{allowed_origin}|{credentials}".encode()).hexdigest(),
                evidence=(
                    f"The response allowed {allowed_origin!r} for a harmless Origin probe; "
                    f"Access-Control-Allow-Credentials is {credentials or 'not set'}. "
                    "Review intended cross-origin access and whether sensitive data is exposed."
                ),
                endpoint_url=endpoint,
            ))

        await log("INFO", f"Received HTTP {status_code}; review {len(findings)} header observation(s)")
        return findings
