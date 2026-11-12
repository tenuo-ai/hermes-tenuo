"""Filesystem-aware workspace validation shared by setup and execution.

Jail validates filesystem reality at call time. It does not pin descriptors or
replace the OS sandbox: Python path-jail does not yet expose Rust's guard API.
"""
from pathlib import Path

from path_jail import Jail


def workspace(folder: str) -> Jail:
    """Resolve an existing project directory, including an explicitly selected symlink."""
    try:
        path = Path(folder).expanduser()
        is_directory = path.is_dir()
    except (OSError, RuntimeError) as exc:
        raise ValueError(f"cannot inspect workspace {folder}: {exc}") from exc
    if not is_directory:
        raise ValueError(f"{folder} is not a folder")
    try:
        jail = Jail(path)
        home = str(Path.home().resolve())
    except (OSError, ValueError, RuntimeError) as exc:
        raise ValueError(f"point Hands at a project folder, not your home folder or / ({exc})") from exc
    if jail.root == home:
        raise ValueError("point Hands at a project folder, not your home folder or /")
    return jail
