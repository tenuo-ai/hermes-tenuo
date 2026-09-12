"""Write a freshly minted warrant into a Hermes profile.

Used by ``setup.sh``. Replaces ``plugins.entries.hermes-tenuo`` with only
the local mint (warrant, trusted_root, signing_key_env) and upserts
``TENUO_SIGNING_KEY`` in the profile ``.env``. Drops leftover plugin keys
and ``TENUO_CONNECT_TOKEN`` so a ``--clone``d profile does not keep another
entry's credentials.
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

_ENV_LINE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$")
_DROP_ENV = ("TENUO_CONNECT_TOKEN",)


def parse_mint_env(text: str) -> dict[str, str]:
    """Parse ``hermes-tenuo mint --output env`` (``export KEY=value`` lines)."""
    out: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("export "):
            line = line[len("export ") :]
        m = _ENV_LINE.match(line)
        if m:
            out[m.group(1)] = m.group(2)
    missing = [k for k in ("TENUO_WARRANT", "TENUO_SIGNING_KEY", "TENUO_TRUSTED_ROOT") if k not in out]
    if missing:
        raise ValueError(f"mint env missing {', '.join(missing)}")
    return out


def upsert_env(path: Path, updates: dict[str, str], drop: tuple[str, ...] = _DROP_ENV) -> None:
    lines: list[str] = []
    if path.exists():
        lines = path.read_text(encoding="utf-8").splitlines()
    seen: set[str] = set()
    out: list[str] = []
    for line in lines:
        m = _ENV_LINE.match(line)
        if not m:
            out.append(line)
            continue
        key = m.group(1)
        if key in drop:
            continue
        if key in updates:
            out.append(f"{key}={updates[key]}")
            seen.add(key)
        else:
            out.append(line)
    for key, value in updates.items():
        if key not in seen:
            out.append(f"{key}={value}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(out) + "\n", encoding="utf-8")


def wire_config(config_path: Path, warrant: str, trusted_root: str) -> None:
    import yaml

    data: dict = {}
    if config_path.exists():
        loaded = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
        if isinstance(loaded, dict):
            data = loaded
    plugins = data.setdefault("plugins", {})
    if not isinstance(plugins, dict):
        plugins = {}
        data["plugins"] = plugins
    enabled = plugins.get("enabled") or []
    if not isinstance(enabled, list):
        enabled = []
    if "hermes-tenuo" not in enabled:
        enabled = list(enabled) + ["hermes-tenuo"]
    plugins["enabled"] = enabled
    entries = plugins.get("entries") or {}
    if not isinstance(entries, dict):
        entries = {}
    entries["hermes-tenuo"] = {
        "warrant": warrant,
        "trusted_root": trusted_root,
        "signing_key_env": "TENUO_SIGNING_KEY",
    }
    plugins["entries"] = entries
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(
        yaml.safe_dump(data, sort_keys=False, default_flow_style=False),
        encoding="utf-8",
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile-dir", required=True, type=Path)
    parser.add_argument("--env-file", required=True, type=Path)
    args = parser.parse_args(argv)
    minted = parse_mint_env(args.env_file.read_text(encoding="utf-8"))
    wire_config(
        args.profile_dir / "config.yaml",
        minted["TENUO_WARRANT"],
        minted["TENUO_TRUSTED_ROOT"],
    )
    upsert_env(args.profile_dir / ".env", {"TENUO_SIGNING_KEY": minted["TENUO_SIGNING_KEY"]})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
