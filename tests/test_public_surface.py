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
