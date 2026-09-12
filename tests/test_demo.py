"""Pin the first-run demo transcript so the README cannot rot."""

from hermes_tenuo.demo import (
    CHILD_ALLOW_SEARCH,
    CHILD_DENY_WRITE,
    CHILD_SCENE,
    CHILD_WHY_WRITE,
    CRON_ALLOW,
    CRON_DENY_PASSWD,
    CRON_DENY_TERMINAL,
    CRON_WHY_OUTSIDE_DIR,
    CRON_WHY_TERMINAL,
    VIEWER_DENY_REPORTS,
    VIEWER_WHY_REPORTS,
    main,
    render_demo,
)


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
    assert CRON_WHY_OUTSIDE_DIR in out
    assert "Constraint 'path' not satisfied" not in out
    assert CRON_DENY_TERMINAL in out
    assert CRON_WHY_TERMINAL in out
    assert CHILD_ALLOW_SEARCH in out
    assert CHILD_DENY_WRITE in out
    assert CHILD_WHY_WRITE in out
    assert VIEWER_DENY_REPORTS in out
    assert VIEWER_WHY_REPORTS in out
    assert "[researcher] ALLOW  write_file" not in out


def test_demo_main_prints_transcript(capsys):
    assert main() == 0
    out = capsys.readouterr().out
    assert CRON_DENY_PASSWD in out
    assert CHILD_DENY_WRITE in out
    assert VIEWER_DENY_REPORTS in out
