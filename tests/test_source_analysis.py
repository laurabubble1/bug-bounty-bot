from pathlib import Path
import json
import subprocess

import pytest

from app import source_analysis
from app.campaign_scope import validate_campaign_web_url
from app.source_analysis import analyze_checkout, repository_matches_scope, validate_repository_url


def test_repository_url_is_limited_to_plain_public_github_repositories() -> None:
    assert validate_repository_url("https://github.com/Example/project") == "https://github.com/Example/project.git"
    assert validate_repository_url("https://github.com/Example/project.git") == "https://github.com/Example/project.git"
    for url in (
        "http://github.com/example/project",
        "https://github.com.example.test/example/project",
        "https://user:secret@github.com/example/project",
        "https://github.com/example/project/tree/main",
        "https://github.com/example/project?next=https://other.test",
    ):
        with pytest.raises(ValueError):
            validate_repository_url(url)


def test_dispatch_and_python_patterns_never_store_matched_secret_values(tmp_path: Path) -> None:
    source = tmp_path / "module.py"
    secret = "AKIAABCDEFGHIJKLMNOP"
    source.write_text(
        "import subprocess\n"
        "import requests\n"
        "value = eval(user_input)\n"
        "subprocess.run(command, shell=True)\n"
        "requests.get(url, verify=False)\n"
        f"key = '{secret}'\n",
        encoding="utf-8",
    )

    selected, findings, file_count = analyze_checkout(tmp_path)

    assert selected == ["credential-pattern-review", "python-risk-pattern-review"]
    assert file_count == 1
    assert {item["title"] for item in findings} >= {
        "Dynamic Python execution call",
        "Subprocess started with shell=True",
        "TLS certificate verification disabled",
        "Possible AWS access key in source",
    }
    assert all(secret not in item["evidence"] for item in findings)


def test_repository_must_match_an_exact_source_asset() -> None:
    url = "https://github.com/example/repository.git"
    assert repository_matches_scope(url, [{
        "identifier": "github.com/example/repository",
        "type": "SOURCE_CODE",
    }])
    assert not repository_matches_scope(url, [{
        "identifier": "github.com/example",
        "type": "SOURCE_CODE",
    }])
    assert not repository_matches_scope(url, [{
        "identifier": "github.com/example/repository",
        "type": "URL",
    }])


def test_campaign_web_url_must_match_exact_https_scope_asset() -> None:
    assets = [{"identifier": "https://api.example.com/v1", "type": "URL"}]
    assert validate_campaign_web_url("https://api.example.com/v1", assets) == "https://api.example.com/v1"
    for target in (
        "https://api.example.com/other",
        "http://api.example.com/v1",
        "https://other.example.com/v1",
    ):
        with pytest.raises(ValueError):
            validate_campaign_web_url(target, assets)


def test_campaign_web_wildcard_scope_requires_a_real_subdomain() -> None:
    assets = [{"identifier": "*.example.com", "type": "WILDCARD"}]
    assert validate_campaign_web_url("https://api.example.com/", assets) == "https://api.example.com/"
    for target in ("https://example.com/", "https://evil-example.com/"):
        with pytest.raises(ValueError):
            validate_campaign_web_url(target, assets)


def test_python_rule_review_covers_deserialization_sql_and_safe_yaml() -> None:
    findings = source_analysis._python_findings(
        "review.py",
        "import pickle, yaml, subprocess\n"
        "pickle.loads(blob)\n"
        "yaml.load(raw)\n"
        "yaml.load(raw, Loader=yaml.SafeLoader)\n"
        "cursor.execute(f'SELECT {value}')\n"
        "subprocess.run(command, shell=True)\n"
        "requests.get(url, verify=False)\n",
    )
    titles = [finding["title"] for finding in findings]
    assert "Pickle deserialization" in titles
    assert "YAML load without SafeLoader" in titles
    assert "Possibly constructed SQL passed to execute" in titles
    assert "Subprocess started with shell=True" in titles
    assert "TLS certificate verification disabled" in titles
    assert titles.count("YAML load without SafeLoader") == 1
    assert source_analysis._python_findings("invalid.py", "def broken(:") == []


def test_analysis_selects_multilanguage_checks_and_skips_large_or_binary_files(tmp_path: Path) -> None:
    (tmp_path / "service.py").write_text("value = eval(data)\n", encoding="utf-8")
    (tmp_path / "handler.ts").write_text("export const handler = 1;\n", encoding="utf-8")
    (tmp_path / "binary.py").write_bytes(b"\xff\xfe")
    (tmp_path / "large.js").write_bytes(b"x" * (source_analysis.MAX_FILE_BYTES + 1))
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "hidden.py").write_text("eval(data)", encoding="utf-8")
    symlink = tmp_path / "linked.py"
    symlink.symlink_to(tmp_path / "service.py")

    selected, findings, file_count = analyze_checkout(tmp_path)

    assert "python-risk-pattern-review" in selected
    assert "semgrep-multilanguage-review" in selected
    assert file_count == 4
    assert len(findings) == 1
    assert findings[0]["path"] == "service.py"


def test_source_review_context_redacts_credentials_and_selects_hotspot_files(tmp_path: Path) -> None:
    auth = tmp_path / "auth.py"
    auth.write_text('token = "sensitive-value-here"\ncheck_session(user)\n', encoding="utf-8")

    excerpts = source_analysis._source_review_context(tmp_path, [])

    assert excerpts == [{
        "path": "auth.py",
        "lines": "1: [redacted credential-like source line]\n2: check_session(user)",
    }]


def test_semgrep_results_are_limited_to_repository_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = tmp_path / "src"
    source.mkdir()
    result_payload = {
        "results": [
            {"path": "src/app.js", "start": {"line": 12}, "extra": {"severity": "ERROR", "message": "Unsafe sink"}},
            {"path": "../../outside.js", "start": {"line": 1}, "extra": {"severity": "WARNING"}},
        ],
    }
    monkeypatch.setattr(
        source_analysis.subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 0, stdout=json.dumps(result_payload), stderr=""),
    )

    findings = source_analysis._semgrep_findings(tmp_path, tmp_path / "semgrep-home")

    assert len(findings) == 1
    assert findings[0]["path"] == "src/app.js"
    assert findings[0]["line"] == 12
    assert findings[0]["severity"] == "high"


def test_semgrep_invalid_results_fail_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        source_analysis.subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 0, stdout="not json", stderr=""),
    )
    with pytest.raises(RuntimeError, match="invalid JSON"):
        source_analysis._semgrep_findings(tmp_path, tmp_path / "semgrep-home")


def test_default_commit_resolution_validates_github_response(monkeypatch: pytest.MonkeyPatch) -> None:
    sha = "b" * 40
    monkeypatch.setattr(
        source_analysis.subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 0, stdout=f"{sha}\tHEAD\n", stderr=""),
    )
    assert source_analysis.resolve_default_commit("https://github.com/example/project") == sha

    monkeypatch.setattr(
        source_analysis.subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 0, stdout="invalid\tHEAD\n", stderr=""),
    )
    with pytest.raises(RuntimeError, match="full commit SHA"):
        source_analysis.resolve_default_commit("https://github.com/example/project")


def test_pinned_checkout_uses_https_and_verifies_the_requested_revision(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sha = "c" * 40
    commands: list[list[str]] = []

    def fake_run(command, **kwargs):
        commands.append(command)
        if "rev-parse" in command:
            return subprocess.CompletedProcess(command, 0, stdout=sha + "\n", stderr="")
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(source_analysis.subprocess, "run", fake_run)
    checkout = tmp_path / "checkout"

    source_analysis.checkout_pinned_commit(
        "https://github.com/example/project", sha.upper(), checkout
    )

    assert checkout.is_dir()
    assert len(commands) == 5
    assert all("-C" in command for command in commands)
    assert commands[2][-3:] == ["--no-recurse-submodules", "origin", sha.lower()]
