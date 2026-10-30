"""Bounded, non-executing checks for a pinned public GitHub source revision."""

import ast
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from urllib.parse import urlsplit

MAX_FILES = 2_000
MAX_FILE_BYTES = 1_000_000
MAX_TOTAL_BYTES = 50_000_000
GIT_TIMEOUT_SECONDS = 120
SEMGREP_TIMEOUT_SECONDS = 120
_SHA_RE = re.compile(r"^(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$")
_SOURCE_EXTENSIONS = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".go": "go",
    ".java": "java",
    ".php": "php",
    ".rb": "ruby",
    ".cs": "csharp",
}
_SECRET_PATTERNS = (
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{30,}\b")),
    ("Private key material", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
)
_SECRET_ASSIGNMENT = re.compile(r"(?i)\b(?:password|passwd|secret|token|api[_-]?key)\s*[:=]\s*['\"].{4,}['\"]")

SOURCE_PROGRAMS = (
    {
        "key": "credential-pattern-review",
        "description": "Looks for a small set of credential-like patterns; matched values are never stored.",
        "languages": ["all"],
        "executes_project_code": False,
    },
    {
        "key": "python-risk-pattern-review",
        "description": "Flags selected risky Python API patterns for manual review.",
        "languages": ["python"],
        "executes_project_code": False,
    },
    {
        "key": "semgrep-multilanguage-review",
        "description": "Runs bundled local rules for risky API patterns across JavaScript, TypeScript, Go, Java, PHP, Ruby, and C#.",
        "languages": ["javascript", "typescript", "go", "java", "php", "ruby", "csharp"],
        "executes_project_code": False,
    },
)


def validate_repository_url(repository_url: str) -> str:
    """Accept only a public HTTPS GitHub repository URL, with no URL tricks."""
    try:
        parsed = urlsplit(repository_url)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Malformed repository URL") from exc
    parts = [part for part in parsed.path.split("/") if part]
    if (
        parsed.scheme != "https"
        or parsed.hostname != "github.com"
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or port not in (None, 443)
        or len(parts) != 2
        or any(part in {".", ".."} for part in parts)
    ):
        raise ValueError("Use a public GitHub repository URL such as https://github.com/owner/repository")
    owner, repo = parts
    if repo.endswith(".git"):
        repo = repo[:-4]
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", owner) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", repo):
        raise ValueError("Repository URL contains unsupported characters")
    return f"https://github.com/{owner}/{repo}.git"


def repository_matches_scope(repository_url: str, scope_assets: list[dict]) -> bool:
    candidate = urlsplit(repository_url)
    candidate_path = candidate.path.rstrip("/").removesuffix(".git").casefold()
    for asset in scope_assets:
        identifier = str(asset.get("identifier", "")).strip()
        asset_type = str(asset.get("type", "")).casefold()
        if not any(token in asset_type for token in ("source", "repository", "github", "git")):
            continue
        normalized = identifier if "://" in identifier else f"https://{identifier}"
        parsed = urlsplit(normalized)
        if parsed.hostname == "github.com" and parsed.path.rstrip("/").removesuffix(".git").casefold() == candidate_path:
            return True
    return False


def _finding(program: str, path: str, line: int, title: str, evidence: str, severity: str = "info") -> dict:
    return {
        "program": program,
        "path": path,
        "line": line,
        "title": title,
        "severity": severity,
        "evidence": evidence,
    }


def _python_findings(path: str, source: str) -> list[dict]:
    try:
        tree = ast.parse(source, filename=path)
    except (SyntaxError, ValueError, RecursionError):
        return []

    findings: list[dict] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = node.func.id if isinstance(node.func, ast.Name) else (
            node.func.attr if isinstance(node.func, ast.Attribute) else ""
        )
        title = ""
        evidence = ""
        if name in {"eval", "exec"}:
            title, evidence = "Dynamic Python execution call", "Review whether untrusted input can reach this call."
        elif name in {"loads", "load"} and isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            module = node.func.value.id
            if module == "pickle":
                title, evidence = "Pickle deserialization", "Pickle data is unsafe when its source is not fully trusted."
            elif module == "yaml" and name == "load":
                safe_loader = any(
                    keyword.arg == "Loader"
                    and isinstance(keyword.value, ast.Attribute)
                    and isinstance(keyword.value.value, ast.Name)
                    and keyword.value.value.id == "yaml"
                    and keyword.value.attr == "SafeLoader"
                    for keyword in node.keywords
                )
                if not safe_loader:
                    title, evidence = "YAML load without SafeLoader", "Review the loader and whether the YAML input can be controlled by an untrusted user."
        if any(keyword.arg == "verify" and isinstance(keyword.value, ast.Constant) and keyword.value.value is False for keyword in node.keywords):
            title, evidence = "TLS certificate verification disabled", "Review whether this request can accept an untrusted server certificate."
        if name in {"run", "Popen", "call", "check_call", "check_output"} and any(
            keyword.arg == "shell" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True
            for keyword in node.keywords
        ):
            title, evidence = "Subprocess started with shell=True", "Review whether user-controlled data can affect the command string."
        if name == "execute" and node.args and isinstance(node.args[0], (ast.JoinedStr, ast.BinOp)):
            title, evidence = "Possibly constructed SQL passed to execute", "Review whether values are passed as bound parameters rather than interpolated into SQL."
        if title:
            findings.append(_finding(
                "python-risk-pattern-review", path, getattr(node, "lineno", 1), title, evidence, "low"
            ))
    return findings


def analyze_checkout(root: Path) -> tuple[list[str], list[dict], int]:
    paths: list[Path] = []
    for path in root.rglob("*"):
        if path.is_file() and not path.is_symlink() and ".git" not in path.parts:
            paths.append(path)
            if len(paths) > MAX_FILES:
                raise ValueError(f"Repository contains more than {MAX_FILES} files; source review stopped at the safety limit")
    paths.sort()
    total_bytes = 0
    python_files = 0
    detected_languages: set[str] = set()
    findings: list[dict] = []
    for path in paths:
        try:
            size = path.stat().st_size
        except OSError:
            continue
        if size > MAX_FILE_BYTES:
            continue
        total_bytes += size
        if total_bytes > MAX_TOTAL_BYTES:
            raise ValueError("Repository source exceeds the 50 MB review limit")
        relative = path.relative_to(root).as_posix()
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for line_number, line in enumerate(text.splitlines(), start=1):
            for label, pattern in _SECRET_PATTERNS:
                if pattern.search(line):
                    findings.append(_finding(
                        "credential-pattern-review", relative, line_number,
                        f"Possible {label} in source", "A credential-like pattern matched; the value was not saved. Check whether it is real and rotate it if exposed.", "medium",
                    ))
                    break
        if path.suffix == ".py":
            python_files += 1
            findings.extend(_python_findings(relative, text))
        language = _SOURCE_EXTENSIONS.get(path.suffix.lower())
        if language:
            detected_languages.add(language)
    selected = ["credential-pattern-review"]
    if python_files:
        selected.append("python-risk-pattern-review")
    if detected_languages - {"python"}:
        selected.append("semgrep-multilanguage-review")
    deduped: dict[tuple, dict] = {}
    for item in findings:
        deduped[(item["program"], item["path"], item["line"], item["title"])] = item
    return selected, list(deduped.values()), len(paths)


def _semgrep_findings(root: Path, home: Path) -> list[dict]:
    rules = Path(__file__).parent / "rules" / "source_review.yml"
    home.mkdir(parents=True, exist_ok=True)
    environment = os.environ.copy()
    environment.update({
        "HOME": str(home),
        "XDG_CACHE_HOME": str(home / ".cache"),
        "SEMGREP_SEND_METRICS": "off",
        "SEMGREP_ENABLE_VERSION_CHECK": "0",
    })
    command = [
        "semgrep", "scan", "--config", str(rules), "--json", "--metrics=off",
        "--disable-version-check", "--timeout", "5", "--max-target-bytes", str(MAX_FILE_BYTES), str(root),
    ]
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=SEMGREP_TIMEOUT_SECONDS,
            env=environment,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(f"Multi-language static analysis could not start or exceeded its time limit ({type(exc).__name__})") from exc
    try:
        payload = json.loads(completed.stdout)
    except (ValueError, TypeError) as exc:
        raise RuntimeError("Multi-language static analysis returned invalid JSON") from exc
    if completed.returncode != 0:
        raise RuntimeError(f"Multi-language static analysis failed (exit {completed.returncode})")

    findings: list[dict] = []
    for result in payload.get("results", [])[:500]:
        extra = result.get("extra", {})
        result_path = Path(str(result.get("path", "")))
        if not result_path.is_absolute():
            result_path = root / result_path
        try:
            relative = result_path.resolve().relative_to(root.resolve()).as_posix()
        except (OSError, ValueError):
            continue
        severity = "high" if str(extra.get("severity", "")).upper() == "ERROR" else "low"
        findings.append(_finding(
            "semgrep-multilanguage-review",
            relative,
            int(result.get("start", {}).get("line", 1)),
            str(extra.get("message") or result.get("check_id") or "Static analysis candidate")[:200],
            "A bundled local static-analysis rule matched this location. Inspect the code and validate reachability and impact manually.",
            severity,
        ))
    return findings


def checkout_pinned_commit(repository_url: str, commit_sha: str, destination: Path) -> None:
    safe_url = validate_repository_url(repository_url)
    if not _SHA_RE.fullmatch(commit_sha):
        raise ValueError("Commit must be a full 40- or 64-character SHA")
    environment = os.environ.copy()
    environment.update({
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ALLOW_PROTOCOL": "https",
        "GIT_LFS_SKIP_SMUDGE": "1",
    })
    destination.mkdir(parents=True, exist_ok=False)

    def run_git(*args: str) -> str:
        completed = subprocess.run(
            ["git", "-c", "http.followRedirects=false", "-c", f"core.hooksPath={os.devnull}", "-C", str(destination), *args],
            check=True,
            capture_output=True,
            text=True,
            timeout=GIT_TIMEOUT_SECONDS,
            env=environment,
        )
        return completed.stdout.strip()

    try:
        run_git("init", "--quiet")
        run_git("remote", "add", "origin", safe_url)
        run_git("fetch", "--quiet", "--depth=1", "--no-tags", "--no-recurse-submodules", "origin", commit_sha.lower())
        run_git("checkout", "--quiet", "--detach", "FETCH_HEAD")
        actual = run_git("rev-parse", "HEAD")
        if actual.lower() != commit_sha.lower():
            raise ValueError("Fetched revision did not match the requested commit")
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        detail = getattr(exc, "stderr", "")
        if isinstance(detail, bytes):
            detail = detail.decode("utf-8", errors="replace")
        raise RuntimeError(f"Could not fetch the pinned commit from GitHub: {str(detail)[:300]}") from exc


def resolve_default_commit(repository_url: str) -> str:
    """Resolve a GitHub repository's current HEAD to a full SHA before checkout."""
    safe_url = validate_repository_url(repository_url)
    environment = os.environ.copy()
    environment.update({
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ALLOW_PROTOCOL": "https",
        "GIT_LFS_SKIP_SMUDGE": "1",
    })
    try:
        completed = subprocess.run(
            ["git", "-c", "http.followRedirects=false", "ls-remote", safe_url, "HEAD"],
            check=True,
            capture_output=True,
            text=True,
            timeout=GIT_TIMEOUT_SECONDS,
            env=environment,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(f"Could not resolve the GitHub default branch ({type(exc).__name__})") from exc
    commit_sha = completed.stdout.split(maxsplit=1)[0] if completed.stdout.strip() else ""
    if not _SHA_RE.fullmatch(commit_sha):
        raise RuntimeError("GitHub did not return a full commit SHA for HEAD")
    return commit_sha.lower()


def _source_review_context(root: Path, findings: list[dict], max_chars: int = 30000) -> list[dict]:
    """Build small, secret-redacted source excerpts for an optional AI review."""
    locations: dict[str, set[int]] = {}
    for item in findings:
        path = str(item.get("path") or "")
        line = item.get("line")
        if path and isinstance(line, int) and path not in locations:
            locations[path] = set()
        if path and isinstance(line, int):
            locations.setdefault(path, set()).add(line)

    if len(locations) < 10:
        for path in sorted(root.rglob("*")):
            if not path.is_file() or path.is_symlink() or ".git" in path.parts:
                continue
            relative = path.relative_to(root).as_posix()
            if path.suffix.lower() not in _SOURCE_EXTENSIONS and path.suffix.lower() not in {".php", ".sql"}:
                continue
            if any(word in relative.casefold() for word in (
                "auth", "permission", "session", "login", "oauth", "token", "query", "sql",
                "serialize", "upload", "download", "file", "path", "crypto", "controller",
            )):
                locations.setdefault(relative, set())
            if len(locations) >= 10:
                break

    excerpts: list[dict] = []
    used_chars = 0
    for relative, lines_of_interest in list(locations.items())[:10]:
        try:
            candidate = (root / relative).resolve()
            candidate.relative_to(root.resolve())
            if candidate.stat().st_size > MAX_FILE_BYTES:
                continue
            lines = candidate.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeDecodeError, ValueError):
            continue
        if lines_of_interest:
            selected_lines: set[int] = set()
            for line_number in lines_of_interest:
                selected_lines.update(range(max(1, line_number - 5), min(len(lines), line_number + 5) + 1))
        else:
            selected_lines = set(range(1, min(len(lines), 80) + 1))
        excerpt_lines = []
        for line_number in sorted(selected_lines):
            line = lines[line_number - 1]
            if any(pattern.search(line) for _, pattern in _SECRET_PATTERNS) or _SECRET_ASSIGNMENT.search(line):
                line = "[redacted credential-like source line]"
            excerpt_lines.append(f"{line_number}: {line}")
        excerpt = "\n".join(excerpt_lines)
        remaining = max_chars - used_chars
        if remaining <= 0:
            break
        excerpt = excerpt[:remaining]
        excerpts.append({"path": relative, "lines": excerpt})
        used_chars += len(excerpt)
    return excerpts


def run_source_programs_with_context(repository_url: str, commit_sha: str) -> tuple[list[str], list[dict], int, list[dict]]:
    """Run bounded local rules and return redacted excerpts for AI review, never persisting code."""
    with tempfile.TemporaryDirectory(prefix="scopeguard-agent-source-") as temp_dir:
        temp_root = Path(temp_dir)
        checkout = temp_root / "repo"
        checkout_pinned_commit(repository_url, commit_sha, checkout)
        selected, findings, count = analyze_checkout(checkout)
        if "semgrep-multilanguage-review" in selected:
            findings.extend(_semgrep_findings(checkout, temp_root / "semgrep-home"))
        deduped: dict[tuple, dict] = {}
        for item in findings:
            deduped[(item["program"], item["path"], item["line"], item["title"])] = item
        final_findings = list(deduped.values())
        context = _source_review_context(checkout, final_findings)
        return selected, final_findings, count, context


def run_source_programs(repository_url: str, commit_sha: str) -> tuple[list[str], list[dict], int]:
    with tempfile.TemporaryDirectory(prefix="scopeguard-source-") as temp_dir:
        temp_root = Path(temp_dir)
        checkout = temp_root / "repo"
        checkout_pinned_commit(repository_url, commit_sha, checkout)
        selected, findings, count = analyze_checkout(checkout)
        if "semgrep-multilanguage-review" in selected:
            findings.extend(_semgrep_findings(checkout, temp_root / "semgrep-home"))
        deduped: dict[tuple, dict] = {}
        for item in findings:
            deduped[(item["program"], item["path"], item["line"], item["title"])] = item
        return selected, list(deduped.values()), count
