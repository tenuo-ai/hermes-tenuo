"""First files a Hermes developer opens must stay local-first."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_plugin_yaml_does_not_prompt_for_connect_token():
    text = (ROOT / "plugin.yaml").read_text()
    assert "TENUO_CONNECT_TOKEN" not in text
    assert "Tenuo Cloud" not in text


def test_examples_do_not_mention_connect_token():
    for path in (ROOT / "examples").glob("*.py"):
        text = path.read_text()
        assert "connect_token" not in text, path.name
        assert "tc_live" not in text, path.name


def test_tree_has_no_hosted_client():
    assert not (ROOT / "mock_cloud.py").exists()
    assert not (ROOT / "hermes_tenuo" / "_cloud.py").exists()
    assert not (ROOT / "tests" / "test_cloud.py").exists()


def test_skill_is_local_only():
    skill = ROOT / "hermes_tenuo" / "skills" / "tenuo-scope" / "SKILL.md"
    text = skill.read_text()
    assert skill.is_file()
    assert "hermes-tenuo mint" in text
    assert "Cloud" not in text
    assert "connect_token" not in text


def test_skill_covers_delegation_practices():
    text = (ROOT / "hermes_tenuo" / "skills" / "tenuo-scope" / "SKILL.md").read_text()
    for needle in (
        "Decide the pattern first",
        "Issuer ≠ agent",
        "child_warrant",
        "grant_builder",
        "set_session_warrant",
        "warrants/<task_id>.warrant",
        "on_denial: log",
        "Do not hand a child the parent's warrant",
        "Anti-patterns",
    ):
        assert needle in text, needle


def test_catalog_entry_matches_manifest():
    import re
    import yaml
    entry = yaml.safe_load((ROOT / "docs" / "plugin-catalog-entry.yaml").read_text())
    manifest = yaml.safe_load((ROOT / "plugin.yaml").read_text())
    assert entry["name"] == manifest["name"] == "hermes-tenuo"
    assert entry["repo"].startswith("https://")
    assert re.fullmatch(r"[0-9a-f]{40}", entry["sha"])
    assert entry["tier"] in ("official", "community")
    assert entry["capabilities"]["provides_hooks"] == manifest["provides_hooks"]
    declared_env = [e["name"] if isinstance(e, dict) else e for e in manifest["requires_env"]]
    assert entry["capabilities"]["requires_env"] == declared_env
    assert not (ROOT / "docs" / "plugin-index-entry.json").exists()


def test_package_and_plugin_versions_agree():
    import re
    pyproject = (ROOT / "pyproject.toml").read_text()
    plugin = (ROOT / "plugin.yaml").read_text()
    py_ver = re.search(r'^version = "([^"]+)"', pyproject, re.M).group(1)
    yaml_ver = re.search(r"^version:\s*(.+)$", plugin, re.M).group(1).strip()
    assert py_ver == yaml_ver == "0.1.1"


def test_readme_keeps_listing_strategy_out():
    text = (ROOT / "README.md").read_text().lower()
    assert "catalog" not in text
    assert "plugin-catalog" not in text
