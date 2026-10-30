from pathlib import Path

import pytest

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
