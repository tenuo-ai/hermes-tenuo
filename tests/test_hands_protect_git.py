"""--protect-git: commands cannot change what git runs in the shared folder."""

from __future__ import annotations

import os
import shlex
import subprocess
import sys
from types import SimpleNamespace

import pytest

from hermes_tenuo.hands import device as device_module
from hermes_tenuo.hands import gitwatch, sandbox
from hermes_tenuo.hands.device import Device, HandsError
from hermes_tenuo.hands.hub import Hub
from tests.test_hands import run, up

locks = pytest.mark.skipif(not sandbox.locks_git(), reason="needs the macOS sandbox")
ME = "git -c user.name=t -c user.email=t@example.com"
_ENV = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com", "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@example.com", "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull}


def git(folder, *args) -> str:
    return subprocess.run(["git", "-C", str(folder), *args], check=True, env=_ENV, capture_output=True, text=True).stdout


@pytest.fixture(autouse=True)
def _direct(monkeypatch):
    for name in ("http_proxy", "https_proxy", "all_proxy", "no_proxy"):
        monkeypatch.delenv(name, raising=False)
        monkeypatch.delenv(name.upper(), raising=False)
    monkeypatch.setenv("no_proxy", "*")


@pytest.fixture
def hub(tmp_path):
    h = Hub(state_dir=tmp_path / "server-state")
    h.listen("127.0.0.1:0")
    yield h
    h.close()


@pytest.fixture
def folder(tmp_path, monkeypatch):
    """A repository with a commit, a file its settings include and a hooks folder they name."""
    monkeypatch.setenv("TENUO_HANDS_HOME", str(tmp_path / "device-state"))
    project = tmp_path / "project"
    project.mkdir()
    git(project, "init", "-q", "-b", "main")
    (project / "README.md").write_text("device readme\n")
    git(project, "add", "README.md")
    git(project, "commit", "-q", "-m", "start")
    return project


def _state(folder) -> tuple:
    """Everything git reads its settings and hooks from, as it is now."""
    meta = folder / ".git"
    hooks = {name: ((meta / "hooks" / name).read_bytes(), os.stat(meta / "hooks" / name).st_mode)
             for name in sorted(os.listdir(meta / "hooks"))}
    return (os.stat(meta).st_ino, (meta / "config").read_bytes(), hooks, sorted(os.listdir(meta)),
            gitwatch.settings(str(folder)))


# --- what is refused ----------------------------------------------------------------

_PLANTS = [
    "git config core.fsmonitor ./watch.sh",
    "git remote add origin https://example.invalid/x.git",
    "printf '[core]\\n\\tfsmonitor = ./watch.sh\\n' >> .git/config",
    "printf '[core]\\n\\tfsmonitor = ./watch.sh\\n' >> .GIT/CONFIG",
    "printf '#!/bin/sh\\n' > .git/hooks/pre-commit",
    "chmod +x .git/hooks/pre-push",
    "mv .git/hooks .git/hooks-aside",
    "printf '[core]\\n\\tfsmonitor = ./watch.sh\\n' > .git/config.worktree",
    "printf '%s\\n' \"$TMPDIR\" > .git/commondir",
    "printf '%s\\n' \"$TMPDIR\" > .git/COMMONDIR",
    "printf x > '.git/config.wor\u212atree'",        # a letter the file system reads as k
    "mkdir -p .git/modules/planted",
    "mkdir -p .git/worktrees/planted",
    "mkdir -p .git/worktrees/other/hooks",
    "printf changed > .git/worktrees/other/gitdir",
    "printf '%s\n' \"$TMPDIR\" > .git/worktrees/other/commondir",
    "mv .git/worktrees/other \"$TMPDIR/other-record\"",
    "mv .git/worktrees \"$TMPDIR/records\"",
    # another name for the same file
    "ln .git/config alias && printf '[core]\\n\\tfsmonitor = ./watch.sh\\n' >> alias",
    "ln -s .git/config link && printf '[core]\\n\\tfsmonitor = ./watch.sh\\n' >> link",
    "ln -s .git meta && printf '#!/bin/sh\\n' > meta/hooks/pre-commit",
    "cp .git/config copy && mv copy .git/config",
    # the repository folder itself, moved aside and made again
    "mv .git .git-aside",
    "mv .git .git-aside && mkdir .git",
    "mv .git \"$TMPDIR/moved-git\" && printf 'gitdir: %s\\n' \"$TMPDIR/moved-git\" > .git",
    # what the settings pull in
    "printf '[core]\\n\\tfsmonitor = ./watch.sh\\n' >> extra.cfg",
    "cp extra.cfg copy.cfg && mv copy.cfg extra.cfg",
    "printf '#!/bin/sh\\n' > tools/hooks/post-checkout",
    "mv tools/hooks tools/hooks-aside",
    "mv tools tools-aside && mkdir -p tools/hooks",
    # a repository of its own, anywhere commands can write
    "git init -q sub",
    "mkdir -p sub/.git",
    "mkdir -p sub/.GIT",
    "mkdir -p sub && printf 'gitdir: %s\\n' \"$TMPDIR\" > sub/.git",
    # a git folder prepared under another name, then renamed into place
    "mkdir -p staged/objects staged/refs home && cp .git/HEAD .git/config staged/ && mv staged home/.git",
    "git init -q \"$TMPDIR/scratch\"",
    "git clone -q . \"$TMPDIR/copy\"",
    "mkdir -p \"$TMPDIR/x/dotgit\" && mv \"$TMPDIR/x/dotgit\" \"$TMPDIR/x/.git\"",
    # one that was already there
    "printf '[core]\\n\\tfsmonitor = ./watch.sh\\n' >> nested/.git/config",
    "printf '#!/bin/sh\\n' > nested/.git/hooks/pre-commit",
    "mv nested \"$TMPDIR/nested\" && printf '[core]\\n\\tfsmonitor = ./watch.sh\\n' >> \"$TMPDIR/nested/.git/config\"",
]


@locks
def test_commands_cannot_change_what_git_runs(hub, folder):
    (folder / "extra.cfg").write_text("[user]\n\tname = t\n")
    (folder / "tools" / "hooks").mkdir(parents=True)
    with open(folder / ".git" / "config", "a") as f:
        f.write("[include]\n\tpath = ../extra.cfg\n[core]\n\thooksPath = tools/hooks\n")
    (folder / ".git" / "hooks" / "pre-push").write_text("#!/bin/sh\n")   # there, but git does not run it yet
    os.chmod(folder / ".git" / "hooks" / "pre-push", 0o644)
    git(folder, "init", "-q", "nested")
    git(folder, "worktree", "add", "-q", str(folder / "other"), "-b", "other")
    nested = (folder / "nested" / ".git" / "config").read_bytes()
    record = sorted(os.listdir(folder / ".git" / "worktrees" / "other"))
    before, included = _state(folder), (folder / "extra.cfg").read_bytes()
    running = up(hub, folder, protect_git=True)
    try:
        for plant in _PLANTS:
            out, code = run(hub, f"{{ {plant} ; }} && echo PLANTED")
            assert "PLANTED" not in out and code != 0, (plant, out)
        temp = running.device.tmp
    finally:
        running.stop()
        running.thread.join(timeout=10)
    assert _state(folder) == before and (folder / "extra.cfg").read_bytes() == included
    assert os.listdir(folder / "tools" / "hooks") == []
    assert not any(".git" in map(str.lower, dirs + files) for _here, dirs, files in os.walk(folder)
                   if _here != str(folder) and not _here.startswith((str(folder / "nested"), str(folder / "other"))))
    assert sorted(os.listdir(folder / ".git" / "worktrees" / "other")) == record
    moved = [os.path.join(here, "config") for here, dirs, _files in os.walk(temp) if here.endswith(os.sep + ".git")]
    assert [open(path, "rb").read() for path in moved] in ([], [nested])   # only the one that was moved there, unchanged
    assert not any("changed git settings" in line for line in running.lines)


@locks
def test_ordinary_git_work_still_succeeds(hub, folder):
    git(folder, "init", "-q", "nested")
    git(folder / "nested", "commit", "-q", "--allow-empty", "-m", "nested start")
    git(folder, "worktree", "add", "-q", str(folder / "other"), "-b", "other")
    running = up(hub, folder, protect_git=True)
    try:
        for command, expected in [
            (f"echo one > a.txt && git add a.txt && {ME} commit -q -m one && git log --oneline | wc -l", "2"),
            ("git checkout -q -b feature && git branch --show-current", "feature"),
            (f"echo two >> a.txt && git diff --stat && {ME} commit -q -a -m two && git status --short", "1 file changed"),
            ("echo three >> a.txt && git stash -q && git stash list | wc -l && git stash pop -q && git diff --stat", "1"),
            ("git checkout -q -- a.txt && git checkout -q main && git branch --list", "feature"),
            (f"git merge -q feature && git tag v1 && git tag --list && {ME} rebase -q HEAD~1", "v1"),
            ("git branch -q -D feature && git branch --list", "main"),
            (f"cd nested && echo n > n.txt && git add n.txt && {ME} commit -q -m in-nested && git log --oneline | wc -l", "2"),
            (f"cd other && echo w > w.txt && git add w.txt && {ME} commit -q -m in-worktree && git log --oneline | wc -l", "2"),
        ]:
            out, code = run(hub, command)
            assert code == 0 and expected in out, (command, out)
    finally:
        running.stop()
        running.thread.join(timeout=10)
    assert git(folder, "log", "--format=%s", "main").split() == ["two", "one", "start"]
    assert git(folder, "status", "--short").split() == ["??", "nested/", "??", "other/"]


@locks
def test_the_summary_and_the_reconnect_command_carry_the_flag(hub, folder):
    (folder / ".hooks").mkdir()
    with open(folder / ".git" / "config", "a") as f:
        f.write("[core]\n\thooksPath = .hooks\n")
    (folder / ".hooks" / "pre-commit").symlink_to("../check.sh")
    device = Device(hub.invite(), str(folder), 600, protect_git=True)
    locked = [line for line in device.summary() if "--protect-git" in line]
    assert len(locked) == 1 and os.path.realpath(folder / ".hooks") in locked[0]
    assert any("links" in line and ".hooks/pre-commit" in line for line in device.summary())
    assert "--protect-git" in shlex.split(device.reconnect_command())
    assert os.path.basename(device.tmp) == "tmp-protect-git"
    assert any(ok and "--protect-git" in text for ok, text in device_module.check(hub.invite(), str(folder), protect_git=True))


@pytest.mark.skipif(sandbox.available() is None, reason="needs sandbox-exec or bubblewrap")
def test_without_the_flag_nothing_changes(hub, folder):
    device = Device(hub.invite(), str(folder), 600)
    assert device.git_locked is None and os.path.basename(device.tmp) == "tmp"
    assert "--protect-git" not in device.reconnect_command()
    assert not any("--protect-git" in line for line in device.summary())
    assert not any("protect-git" in text for _ok, text in device_module.check(hub.invite(), str(folder)))


def test_the_sandbox_profile_gains_git_rules_only_when_asked(tmp_path):
    folder, temp = str(tmp_path / "project"), str(tmp_path / "temp")
    plain = sandbox._mac_profile(folder, temp)
    assert "[gG][iI][tT]" not in plain
    assert sandbox._mac_profile(folder, temp, git_locked=None) == plain
    locked = sandbox._mac_profile(folder, temp, git_locked=[f"{folder}/tools/hooks"])
    added = [line for line in locked.splitlines() if line not in plain.splitlines()]
    assert added and all(line.startswith("(deny file-write") for line in added)   # it only ever takes away
    assert f'(deny file-write* (subpath "{folder}/tools/hooks"))' in added
    assert f'(deny file-write-unlink (literal "{folder}/tools"))' in added


# --- where it cannot hold -----------------------------------------------------------

@pytest.mark.parametrize("kind", ["bwrap", None])
def test_the_flag_is_refused_where_the_sandbox_cannot_hold_it(folder, tmp_path, monkeypatch, kind):
    monkeypatch.setattr(sandbox, "_probe", [kind])
    with pytest.raises(HandsError, match="macOS sandbox"):
        Device(None, str(folder), 600, protect_git=True, allow_unsandboxed=kind is None)
    with pytest.raises(sandbox.SandboxUnavailable, match="macOS sandbox"):
        sandbox.wrap(str(folder), str(tmp_path), ["true"], git_locked=[], allow_unsandboxed=True)
    found = device_module.check(None, str(folder), protect_git=True, allow_unsandboxed=kind is None)
    assert any(ok is False and "macOS sandbox" in text for ok, text in found)
    assert not (tmp_path / "device-state" / "tmp-protect-git").exists()


def test_preview_and_check_take_the_flag(folder, monkeypatch, capsys):
    from hermes_tenuo.cli import cmd_hands
    args = SimpleNamespace(hands_command="up", preview=True, invite="hands://127.0.0.1:1/x#" + "0" * 8, dir=str(folder),
                           ttl="1h", read_only=False, network=False, no_sandbox=False, read_home=False, read=None,
                           protect_git=True)
    monkeypatch.setattr(device_module.wire.Invite, "parse", staticmethod(lambda _line: SimpleNamespace(url="http://127.0.0.1:1")))
    code = cmd_hands(args)
    said = capsys.readouterr()
    if sys.platform == "darwin":
        assert code == 0 and "locked (--protect-git)" in said.out
    else:
        assert code == 1 and "macOS sandbox" in said.err
    args.protect_git = False
    assert cmd_hands(args) == 0 and "protect-git" not in capsys.readouterr().out


def _sources(folder, tmp_path):
    temp = tmp_path / "temp"
    temp.mkdir(exist_ok=True)
    return gitwatch.sources(str(folder), also=(str(temp),))


def test_sources_names_what_the_settings_pull_in(folder, tmp_path):
    assert _sources(folder, tmp_path) == ([], [], [])
    (folder / "extra.cfg").write_text("[include]\n\tpath = more.cfg\n")
    (folder / "more.cfg").write_text("[user]\n\tname = t\n")
    (folder / ".hooks").mkdir()
    (folder / ".hooks" / "pre-commit").symlink_to("../check.sh")
    with open(folder / ".git" / "config", "a") as f:
        f.write("[include]\n\tpath = ../extra.cfg\n\tpath = /etc/hosts\n[core]\n\thooksPath = .hooks\n")
    paths, problems, notes = _sources(folder, tmp_path)
    assert sorted(paths) == [str(folder / name) for name in (".hooks", "extra.cfg", "more.cfg")]
    assert problems == [] and notes == [".hooks/pre-commit (cannot be checked)"]
    assert gitwatch.sources(str(tmp_path / "temp")) == ([], [], [])           # not a repository: nothing to name


@pytest.mark.parametrize("arrange, problem", [
    (lambda f: (f / ".git" / "config").open("a").write("[include]\n\tpath = ../absent.cfg\n"), "does not exist"),
    (lambda f: (f / ".git" / "config").open("a").write("[core]\n\thooksPath = absent\n"), "does not exist"),
    (lambda f: (f / ".git" / "config").open("a").write("[core]\n\thooksPath = .\n"), "whole folder"),
    (lambda f: (f / ".git" / "commondir").write_text("../elsewhere\n") and (f / "elsewhere").mkdir(), "commondir"),
    (lambda f: (f / ".git" / "commondir").write_text("/var/empty\n"), "commondir"),
    (lambda f: (f / ".git" / "commondir").write_text(".\n"), "commondir"),          # even one that changes nothing yet
    (lambda f: (os.rename(f / ".git" / "config", f / "real.cfg"),
                (f / ".git" / "config").symlink_to("../real.cfg")), "cannot be checked"),
    (lambda f: ((f / "hooks-here").mkdir(), (f / ".hooks").symlink_to("hooks-here"),
                (f / ".git" / "config").open("a").write("[core]\n\thooksPath = .hooks\n")), "cannot be checked"),
    (lambda f: (os.rename(f / ".git", f / "meta"), (f / ".git").write_text("gitdir: meta\n")), "commands can write"),
    (lambda f: (os.rename(f / ".git", f.parent / "temp"),                            # the commands' temp folder
                (f / ".git").write_text(f"gitdir: {f.parent / 'temp'}\n")), "commands can write"),
    (lambda f: (os.rename(f / ".git", f / "x"), (f / ".git").write_text("not a pointer\n")), "does not point"),
    (lambda f: (os.rename(f / ".git", f / "x"), (f / ".git").write_text("gitdir: /var/empty/none\n")), "does not point"),
    (lambda f: (os.rename(f / ".git", f / "x"), (f / ".git").symlink_to("x")), "cannot be checked"),
])
def test_sources_says_when_it_cannot_name_everything(folder, tmp_path, arrange, problem):
    arrange(folder)
    _paths, problems, _notes = _sources(folder, tmp_path)
    assert any(problem in text for text in problems), problems


# --- a shared folder whose git folder is elsewhere ----------------------------------

@pytest.fixture
def worktree(folder, tmp_path):
    """A linked worktree of the repository in `folder`. Its settings are in the main
    repository, outside what is shared, and pull in a file and a hooks folder inside it."""
    (tmp_path / "shared.cfg").write_text(f"[include]\n\tpath = {tmp_path / 'tree' / 'extra.cfg'}\n")
    with open(folder / ".git" / "config", "a") as f:
        f.write(f"[core]\n\thooksPath = .hooks\n[include]\n\tpath = {tmp_path / 'shared.cfg'}\n")
    tree = tmp_path / "tree"
    git(folder, "worktree", "add", "-q", str(tree), "-b", "tree")
    (tree / ".hooks").mkdir()
    (tree / "extra.cfg").write_text("[user]\n\tname = t\n")
    return tree


def test_sources_follows_a_worktrees_settings_out_of_the_folder_and_back(worktree, tmp_path):
    paths, problems, notes = _sources(worktree, tmp_path)
    assert sorted(paths) == [str(worktree / ".hooks"), str(worktree / "extra.cfg")] and not problems and not notes
    assert gitwatch.loose(str(worktree), (), paths) == ([], True)
    # Without the flag nothing outside the shared folder is read.
    assert "core.hookspath" not in gitwatch.settings(str(worktree))
    os.link(worktree / ".git", worktree / "alias")
    assert gitwatch.loose(str(worktree)) == ([".git has a second name (a hard link)"], True)


def test_sources_reads_what_an_included_file_outside_the_folder_pulls_in(folder, tmp_path):
    (tmp_path / "outside.cfg").write_text("[core]\n\thooksPath = .hooks\n")
    (folder / ".hooks").mkdir()
    with open(folder / ".git" / "config", "a") as f:
        f.write(f"[include]\n\tpath = {tmp_path / 'outside.cfg'}\n")
    assert _sources(folder, tmp_path) == ([str(folder / ".hooks")], [], [])
    os.unlink(tmp_path / "outside.cfg")
    (folder / "inside.cfg").write_text("")
    (tmp_path / "outside.cfg").symlink_to(folder / "link")           # reached through a link commands can change
    (folder / "link").symlink_to(tmp_path / "elsewhere.cfg")
    (tmp_path / "elsewhere.cfg").write_text("")
    _paths, problems, _notes = _sources(folder, tmp_path)
    assert any("outside.cfg (cannot be checked)" in text for text in problems), problems


@locks
def test_a_shared_worktree_is_locked_too(hub, worktree):
    pointer = (worktree / ".git").read_bytes()
    running = up(hub, worktree, protect_git=True)
    try:
        assert any("--protect-git" in line and str(worktree / ".hooks") in line for line in running.lines)
        for plant in [
            "printf 'gitdir: %s\n' \"$TMPDIR\" > .git",
            "mv .git .git-aside",
            "cp .git copy && mv copy .git",
            "ln .git alias",
            "printf '#!/bin/sh\n' > .hooks/pre-commit",
            "mv .hooks .hooks-aside",
            "printf '[core]\n\tfsmonitor = ./watch.sh\n' >> extra.cfg",
        ]:
            out, code = run(hub, f"{{ {plant} ; }} && echo PLANTED")
            assert "PLANTED" not in out and code != 0, (plant, out)
        out, code = run(hub, "echo work > notes.txt && cat notes.txt")
        assert (out.strip(), code) == ("work", 0)
    finally:
        running.stop()
        running.thread.join(timeout=10)
    assert (worktree / ".git").read_bytes() == pointer and os.listdir(worktree / ".hooks") == []
    assert (worktree / "extra.cfg").read_text() == "[user]\n\tname = t\n"


# --- what is already there and would not be held ------------------------------------

def _module(folder, name):
    meta = folder / ".git" / "modules" / name
    (meta / "objects" / "ab").mkdir(parents=True)
    (meta / "hooks").mkdir()
    for plain in ("HEAD", "config"):
        (meta / plain).write_text("")
    return meta


@pytest.mark.parametrize("arrange, problem", [
    (lambda f: os.link(f / ".git" / "config", f / "alias"), ".git/config has a second name"),
    (lambda f: os.link(f / ".git" / "hooks" / "pre-commit.sample", f / "alias"), "pre-commit.sample has a second name"),
    (lambda f: os.link(_module(f, "lib") / "config", f / "alias"), ".git/modules/lib/config has a second name"),
    (lambda f: os.link(_module(f, "objects") / "config", f / "alias"), ".git/modules/objects/config has a second name"),
    (lambda f: (os.rename(_module(f, "lib") / "config", f / "module-settings"),
                (f / ".git" / "modules" / "lib" / "config").symlink_to("../../../module-settings")), "config is a link"),
    (lambda f: (os.rename(f / ".git" / "modules", f / "elsewhere"),
                (f / ".git" / "modules").symlink_to("../elsewhere")), ".git/modules is a link"),
    (lambda f: os.link(f / "other-tree" / ".git", f / "alias"), "other-tree/.git has a second name"),
    (lambda f: os.link(f / ".git" / "worktrees" / "other-tree" / "commondir", f / "alias"), "commondir has a second name"),
    (lambda f: (f / ".git" / "worktrees" / "other-tree" / "commondir").write_text("../../../unheld\n"), "does not hold"),
    (lambda f: os.link(f / "nested" / ".git" / "config", f / "alias"), "nested/.git/config has a second name"),
    (lambda f: os.link(f / "deep" / "er" / "nested" / ".git" / "hooks" / "pre-commit.sample", f / "alias"), "has a second name"),
    (lambda f: (f / "nested" / ".git" / "commondir").write_text(".\n"), "nested/.git/commondir"),
    (lambda f: (os.rename(f / "nested" / ".git", f / "meta"), (f / "nested" / ".git").write_text("gitdir: ../meta\n")),
     "nested/.git points to a git folder the lock does not hold"),
    (lambda f: (os.rename(f / "nested" / ".git", f / "meta"), (f / "nested" / ".git").symlink_to("../meta")),
     "nested/.git is a link"),
])
def test_the_folder_is_looked_through_for_what_the_lock_would_not_hold(folder, arrange, problem):
    git(folder, "init", "-q", "nested")
    git(folder, "init", "-q", "deep/er/nested")
    git(folder, "worktree", "add", "-q", str(folder / "other-tree"), "-b", "other-tree")
    (folder / "pointed").mkdir()
    (folder / "pointed" / ".git").write_text("gitdir: ../.git/modules/lib\n")       # held by its name: fine
    meta = _module(folder, "kept")
    (meta / "objects" / "ab" / ("0" * 38)).write_text("")
    os.link(meta / "objects" / "ab" / ("0" * 38), folder / "shared-object")           # objects may be shared
    (folder / ".git" / "hooks" / "pre-commit").symlink_to("../../check.sh")           # a hook may be a link
    assert gitwatch.loose(str(folder)) == ([], True)
    arrange(folder)
    problems, complete = gitwatch.loose(str(folder))
    assert complete and any(problem in text for text in problems), problems


def test_a_folder_too_large_to_look_through_is_not_called_clean(folder, monkeypatch):
    for n in range(5):
        (folder / f"d{n}").mkdir()
    monkeypatch.setattr(gitwatch, "_WALKED", 3)
    assert gitwatch.loose(str(folder))[1] is False
    monkeypatch.setattr(gitwatch, "_WALKED", 100)
    monkeypatch.setattr(gitwatch, "_CHECKED", 3)
    assert gitwatch.loose(str(folder))[1] is False


@locks
def test_the_device_does_not_start_with_a_lock_that_would_not_hold(hub, folder):
    os.link(folder / ".git" / "config", folder / "alias")
    with pytest.raises(HandsError, match="second name"):
        Device(hub.invite(), str(folder), 600, protect_git=True)
    os.unlink(folder / "alias")
    with open(folder / ".git" / "config", "a") as f:
        f.write("[include]\n\tpath = ../absent.cfg\n")
    with pytest.raises(HandsError, match="does not exist"):
        Device(hub.invite(), str(folder), 600, protect_git=True)
    assert any(ok is False and "does not exist" in text
               for ok, text in device_module.check(hub.invite(), str(folder), protect_git=True))
    assert not hub.sessions()


@pytest.mark.parametrize("location", [".git/objects/nested", "deep/nested"])
def test_repositories_inside_metadata_are_inspected(folder, location):
    nested = folder / location
    nested.mkdir(parents=True)
    git(nested, "init", "-q")
    os.link(nested / ".git" / "config", folder / "alias")
    problems, complete = gitwatch.loose(str(folder))
    assert complete and any("has a second name" in p for p in problems)


def test_module_commondir_cannot_redirect_to_writable_metadata(folder):
    meta = _module(folder, "lib")
    (meta / "commondir").write_text("../../../unheld\n")
    problems, complete = gitwatch.loose(str(folder))
    assert complete and any("commondir" in p and "does not hold" in p for p in problems)


def test_unreadable_workspace_is_not_called_clean(folder, monkeypatch):
    original = os.scandir
    hidden = folder / "hidden"
    hidden.mkdir()
    def unreadable(path):
        if os.fspath(path) == str(hidden):
            raise PermissionError("unreadable")
        return original(path)
    monkeypatch.setattr(os, "scandir", unreadable)
    problems, _ = gitwatch.loose(str(folder))
    assert any("hidden cannot be read" in p for p in problems)


def test_settings_fifo_is_not_called_clean(folder):
    config = folder / ".git" / "config"
    config.unlink()
    os.mkfifo(config)
    problems, _ = gitwatch.loose(str(folder))
    assert any("config is not a regular" in p for p in problems)


def test_writable_temp_metadata_is_also_inspected(folder, tmp_path):
    temp = tmp_path / "temp"
    temp.mkdir()
    git(temp, "init", "-q")
    os.link(temp / ".git" / "config", temp / "alias")
    problems, _ = gitwatch.loose(str(folder), also=(str(temp),))
    assert any("has a second name" in p for p in problems)



def test_outside_include_cannot_traverse_writable_directory_link(folder, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "config").write_text("[user]\nname = t\n")
    (folder / "redirect").symlink_to(outside, target_is_directory=True)
    alias = tmp_path / "alias"
    alias.symlink_to(folder / "redirect", target_is_directory=True)
    with (folder / ".git" / "config").open("a") as stream:
        stream.write(f"[include]\npath = {alias}/config\n")
    _paths, problems, _notes = _sources(folder, tmp_path)
    assert any("cannot be checked" in p for p in problems)



def test_included_settings_do_not_get_the_shared_object_exemption(folder):
    config = folder / ".git" / "objects" / "pack" / "settings.pack"
    config.parent.mkdir(exist_ok=True)
    config.write_text("[user]\nname = t\n")
    os.link(config, folder / "alias")
    problems, _ = gitwatch.loose(str(folder), paths=(str(config),))
    assert any("has a second name" in p for p in problems)



def test_external_included_settings_hard_link_is_rejected(folder, tmp_path):
    outside = tmp_path / "external.cfg"
    outside.write_text("[user]\nname = t\n")
    os.link(outside, folder / "alias")
    with (folder / ".git" / "config").open("a") as stream:
        stream.write(f"[include]\npath = {outside}\n")
    assert any("cannot be checked" in p for p in _sources(folder, tmp_path)[1])


@pytest.mark.parametrize("layout", ["directory-link", "hook-hard-link"])
def test_shared_worktree_external_default_hooks_are_checked(folder, tmp_path, layout):
    import shutil
    worktree = tmp_path / "worktree"
    git(folder, "worktree", "add", "-q", str(worktree), "-b", "worktree")
    hooks = folder / ".git" / "hooks"
    if layout == "directory-link":
        shutil.rmtree(hooks)
        (worktree / "local-hooks").mkdir()
        hooks.symlink_to(worktree / "local-hooks", target_is_directory=True)
    else:
        (hooks / "pre-commit").write_text("#!/bin/sh\n")
        os.link(hooks / "pre-commit", worktree / "alias")
    assert any("hook" in p for p in _sources(worktree, tmp_path)[1])



@pytest.mark.parametrize("layout", ["directory-link", "hook-hard-link"])
def test_explicit_external_hooks_are_checked(folder, tmp_path, layout):
    outside = tmp_path / "outside-hooks"
    outside.mkdir()
    if layout == "directory-link":
        (folder / "bridge").symlink_to(outside, target_is_directory=True)
        alias = tmp_path / "alias-hooks"
        alias.symlink_to(folder / "bridge", target_is_directory=True)
    else:
        (outside / "pre-commit").write_text("#!/bin/sh\n")
        os.link(outside / "pre-commit", folder / "alias")
        alias = outside
    with (folder / ".git" / "config").open("a") as stream:
        stream.write(f"[core]\nhooksPath = {alias}\n")
    assert any("hook" in p for p in _sources(folder, tmp_path)[1])
