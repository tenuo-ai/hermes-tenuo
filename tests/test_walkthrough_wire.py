"""examples/walkthrough/wire_profile.py — clone-safe profile wiring."""

from __future__ import annotations

import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "examples" / "walkthrough"))

from wire_profile import parse_mint_env, upsert_env, wire_config  # noqa: E402


def test_parse_mint_env_strips_export():
    parsed = parse_mint_env(
        "export TENUO_WARRANT=w\nexport TENUO_SIGNING_KEY=s\nexport TENUO_TRUSTED_ROOT=r\n"
    )
    assert parsed == {
        "TENUO_WARRANT": "w",
        "TENUO_SIGNING_KEY": "s",
        "TENUO_TRUSTED_ROOT": "r",
    }


def test_wire_config_replaces_cloned_plugin_entry(tmp_path: Path):
    cfg = tmp_path / "config.yaml"
    cfg.write_text(
        yaml.safe_dump(
            {
                "model": {"default": "gpt-4o-mini"},
                "plugins": {
                    "enabled": ["other", "hermes-tenuo"],
                    "entries": {
                        "other": {"x": 1},
                        "hermes-tenuo": {
                            "warrant": "old",
                            "trusted_root": "old-root",
                            "signing_key_env": "TENUO_SIGNING_KEY",
                            "connect_token": "must-not-survive",
                            "child_warrant": "old-child",
                        },
                    },
                },
            }
        ),
        encoding="utf-8",
    )
    wire_config(cfg, "new-warrant", "new-root")
    data = yaml.safe_load(cfg.read_text(encoding="utf-8"))
    assert data["model"]["default"] == "gpt-4o-mini"
    assert data["plugins"]["enabled"] == ["other", "hermes-tenuo"]
    assert data["plugins"]["entries"]["other"] == {"x": 1}
    assert data["plugins"]["entries"]["hermes-tenuo"] == {
        "warrant": "new-warrant",
        "trusted_root": "new-root",
        "signing_key_env": "TENUO_SIGNING_KEY",
    }


def test_upsert_env_replaces_key_and_drops_connect_token(tmp_path: Path):
    env = tmp_path / ".env"
    env.write_text(
        "OPENAI_API_KEY=keep-me\nTENUO_SIGNING_KEY=old\nTENUO_CONNECT_TOKEN=drop-me\n",
        encoding="utf-8",
    )
    upsert_env(env, {"TENUO_SIGNING_KEY": "new"})
    text = env.read_text(encoding="utf-8")
    assert "OPENAI_API_KEY=keep-me" in text
    assert "TENUO_SIGNING_KEY=new" in text
    assert "TENUO_CONNECT_TOKEN" not in text
    assert "old" not in text
    assert "drop-me" not in text
