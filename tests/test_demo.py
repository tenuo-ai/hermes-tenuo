"""Pin the first-run demo transcript so the authorization reference cannot rot."""

from pathlib import Path

from hermes_tenuo.demo import (
    CHILD_ALLOW_SEARCH,
    CHILD_DENY_WRITE,
    CHILD_SCENE,
    CHILD_WHY_WRITE,
    CRON_ALLOW,
    CRON_DENY_EXPIRED,
    CRON_DENY_PASSWD,
    CRON_DENY_TERMINAL,
    CRON_WHY_EXPIRED,
    CRON_WHY_OUTSIDE_DIR,
    CRON_WHY_TERMINAL,
    VIEWER_DENY_REPORTS,
    VIEWER_WHY_REPORTS,
    main,
    render_demo,
)

REFERENCE = Path(__file__).resolve().parents[1] / "docs" / "reference.md"


def test_demo_transcript_pins():
    out = render_demo()
    assert "No Hermes process, no API key." in out
    assert "That slip is a Tenuo warrant" in out
    assert "== Cron ==" in out
    assert "== delegate_task ==" in out
    assert CHILD_SCENE in out
    assert "the chain is verified" not in out.lower()
    assert "== Gateway ==" in out
    assert "Same server, two slips." in out
    assert CRON_ALLOW in out
    assert CRON_DENY_PASSWD in out
    assert "Constraint 'path' not satisfied: value does not match constraint  ← " + CRON_WHY_OUTSIDE_DIR in out
    assert CRON_DENY_TERMINAL in out
    assert "Tool 'terminal' is not authorized  ← " + CRON_WHY_TERMINAL in out
    assert "(one second later)" in out
    assert CRON_DENY_EXPIRED in out
    assert "Warrant has expired  ← " + CRON_WHY_EXPIRED in out
    assert CHILD_ALLOW_SEARCH in out
    assert CHILD_DENY_WRITE in out
    assert "Tool 'write_file' is not authorized  ← " + CHILD_WHY_WRITE in out
    assert VIEWER_DENY_REPORTS in out
    assert VIEWER_WHY_REPORTS in out
    assert "[researcher] ALLOW  write_file" not in out


def test_demo_matches_reference_fence():
    text = REFERENCE.read_text()
    marker = "hermes-tenuo demo\n```\n\n```text\n"
    start = text.find(marker)
    assert start != -1
    start += len(marker)
    end = text.find("\n```", start)
    assert end != -1
    assert render_demo() == text[start:end] + "\n"


def test_demo_main_prints_transcript(capsys):
    assert main() == 0
    out = capsys.readouterr().out
    assert CRON_DENY_PASSWD in out
    assert CHILD_DENY_WRITE in out
    assert VIEWER_DENY_REPORTS in out


def test_the_one_second_warrant_is_minted_early_in_a_second(monkeypatch):
    """The transcript must not depend on when in a second the demo happens to start."""
    import hermes_tenuo.demo as demo

    slept = []
    for now, waits in ((1000.05, False), (1000.30, False), (1000.31, True), (1000.97, True)):
        slept.clear()
        monkeypatch.setattr(demo.time, "time", lambda now=now: now)
        monkeypatch.setattr(demo.time, "sleep", slept.append)
        demo._start_of_a_second()
        assert bool(slept) is waits, now
        if waits:
            assert 0 < slept[0] <= 0.72 and (now + slept[0]) % 1 < 0.05
