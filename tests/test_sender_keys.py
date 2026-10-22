"""Who is talking: sender_keys reads Hermes' gateway context, else its session store."""
import sys
import types

import pytest

from hermes_tenuo.local_guard import sender_keys


@pytest.fixture
def gateway(monkeypatch):
    env = {}
    module = types.SimpleNamespace(get_session_env=lambda name, default="": env.get(name, default))
    monkeypatch.setitem(sys.modules, "gateway", types.SimpleNamespace(session_context=module))
    monkeypatch.setitem(sys.modules, "gateway.session_context", module)
    return env


@pytest.fixture
def store(monkeypatch):
    rows = {}

    class SessionDB:
        def __init__(self, *args, **kwargs):
            pass

        def get_session(self, session_id):
            return rows.get(session_id)

    monkeypatch.setitem(sys.modules, "hermes_state", types.SimpleNamespace(SessionDB=SessionDB))
    return rows


def _context(gateway, platform, user="", chat=""):
    gateway.update(HERMES_SESSION_PLATFORM=platform, HERMES_SESSION_USER_ID=user, HERMES_SESSION_CHAT_ID=chat)


def test_user_comes_before_chat(gateway, store):
    _context(gateway, "telegram", user="111", chat="-900")
    assert sender_keys("s") == ["telegram:111", "telegram:-900"]


def test_people_sharing_a_chat_get_their_own_key_first(gateway, store):
    _context(gateway, "telegram", user="111", chat="-900")
    first = sender_keys("s")
    _context(gateway, "telegram", user="222", chat="-900")
    second = sender_keys("s")
    assert first[0] == "telegram:111" and second[0] == "telegram:222"
    assert first[1] == second[1] == "telegram:-900"


def test_direct_message_where_user_and_chat_match(gateway, store):
    _context(gateway, "telegram", user="111", chat="111")
    assert sender_keys("s") == ["telegram:111"]


def test_session_store_when_there_is_no_gateway_context(gateway, store):
    store["s"] = {"source": "discord", "user_id": "42", "chat_id": "chan"}
    assert sender_keys("s") == ["discord:42", "discord:chan"]
    assert sender_keys("unknown") == []


def test_cli_sessions_have_no_sender(gateway, store):
    _context(gateway, "cli", user="me")
    assert sender_keys("s") == []
    gateway.clear()
    store["s"] = {"source": "cli", "user_id": "me"}
    assert sender_keys("s") == []
