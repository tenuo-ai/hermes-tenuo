"""Pin the first-run demo transcript so the README cannot rot."""

from hermes_tenuo.demo import (
    CHILD_ALLOW_SEARCH,
    CHILD_DENY_WRITE,
    CHILD_SCENE,
    CRON_ALLOW,
    CRON_DENY_PASSWD,
    CRON_DENY_TERMINAL,
    VIEWER_DENY_REPORTS,
    main,
    render_demo,
)


def test_demo_transcript_pins():
    out = render_demo()
    assert "No Hermes process, no API key." in out
    assert "== Cron ==" in out
    assert "== delegate_task ==" in out
    assert CHILD_SCENE in out
    assert "== Gateway ==" in out
    assert CRON_ALLOW in out
    assert CRON_DENY_PASSWD in out
    assert "Constraint 'path' not satisfied" in out
    assert CRON_DENY_TERMINAL in out
    assert "Tool 'terminal' is not authorized" in out
    assert CHILD_ALLOW_SEARCH in out
    assert CHILD_DENY_WRITE in out
    assert "Tool 'write_file' is not authorized" in out
    assert VIEWER_DENY_REPORTS in out
    assert "[researcher] ALLOW  write_file" not in out


def test_demo_main_prints_transcript(capsys):
    assert main() == 0
    out = capsys.readouterr().out
    assert CRON_DENY_PASSWD in out
    assert CHILD_DENY_WRITE in out
    assert VIEWER_DENY_REPORTS in out
