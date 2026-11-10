"""Regressions from the PR 55 security and lifecycle review."""

import os
import subprocess
import sys
import pytest
from tenuo import SigningKey, Warrant, Subpath, Wildcard
from hermes_tenuo.hermes_guard import HermesGuard
from hermes_tenuo.delegation import parse_plan


def guard(prefix=False, planned=False):
    issuer, holder = SigningKey.generate(), SigningKey.generate()
    prefix = 'tool:' if prefix else ''
    warrant = (Warrant.mint_builder().holder(holder.public_key)
               .capability(prefix+'read_file', path=Subpath('/data'))
               .capability(prefix+'web_search', query=Wildcard())
               .capability(prefix+'delegate_task').capability('delegate_task').ttl(600).mint(issuer))
    plan = None
    if planned:
        tools = {prefix+'read_file': {}, prefix+'delegate_task': {}}
        plan = parse_plan({'version': 1, 'root': {'tools': tools},
                           'levels': [{'ttl_seconds': 300, 'tools': tools},
                                      {'ttl_seconds': 60, 'tools': {prefix+'read_file': {}}}]})
    child_template = None
    if prefix and not planned:
        child_template = (Warrant.mint_builder().holder(holder.public_key)
                          .capability(prefix+'delegate_task').ttl(300).mint(issuer))
    events = []
    g = HermesGuard(warrant=warrant, signing_key=holder, trusted_roots=[issuer.public_key],
                    delegation_plan=plan, child_warrant=child_template, audit_callback=events.append)
    return g, events


def test_missing_ids_must_not_recover_root_authority():
    g, _ = guard()
    assert g.pre_tool_call('delegate_task', {'goal':'web only', 'toolsets':['web']}, session_id='p') is None
    g.on_subagent_start('p','c',child_goal='web only',child_task_id='tc')
    assert g.pre_tool_call('read_file', {'path':'/data/secret'}, session_id='c') is not None
    assert g.pre_tool_call('read_file', {'path':'/data/secret'}) is not None


@pytest.mark.parametrize('planned', [False, True])
def test_prefixed_delegation_can_continue(planned):
    g, _ = guard(prefix=True, planned=planned)
    assert g.pre_tool_call('delegate_task', {'goal':'level1'}, session_id='p') is None
    g.on_subagent_start('p','c',child_goal='level1')
    child, _ = g._resolve_warrant('c')
    assert 'tool:delegate_task' in child.tools
    assert not child.is_terminal()
    assert g.pre_tool_call('delegate_task', {'goal':'level2'}, session_id='c') is None


@pytest.mark.parametrize('post', [False, True])
def test_unauthorized_child_denial_is_audited(post):
    g, events = guard()
    g.on_subagent_start('p','stray',child_goal='not staged')
    assert g.pre_tool_call('read_file', {'path':'/data/file'},session_id='stray',tool_call_id='denied')
    if post:
        g.post_tool_call('read_file', {}, '{}', session_id='stray',tool_call_id='denied')
    assert events and events[-1].decision == 'DENY', [(e.decision,e.reason) for e in events]


def test_rejected_grant_has_denial_without_post():
    g, events = guard()
    result = g.pre_tool_call('delegate_task', {'goal':'g','toolsets':[]},session_id='p',tool_call_id='empty')
    assert result and result['action'] == 'block'
    assert events and events[-1].decision == 'DENY', [(e.decision,e.reason) for e in events]


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFOs are POSIX-only")
def test_fifo_plan_is_rejected_instead_of_blocking(tmp_path):
    p = tmp_path / 'plan.json'
    os.mkfifo(p, 0o600)
    proc = subprocess.Popen([sys.executable, '-c',
        'from hermes_tenuo.delegation import load_plan; import sys; load_plan(sys.argv[1])', str(p)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        _, stderr = proc.communicate(timeout=2)
        assert proc.returncode != 0
        assert b"must be a regular file" in stderr, stderr
    except subprocess.TimeoutExpired:
        pytest.fail('load_plan blocks on FIFO instead of rejecting non-regular file')
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.communicate()


@pytest.mark.parametrize("status", ["cancelled", "timeout", "error"])
def test_cancelled_invocation_cannot_claim_later_retry_authority(status):
    from hermes_tenuo._guard import PluginGuard
    g, _ = guard()
    adapter = PluginGuard(g)
    assert adapter.pre_tool_call_hook('delegate_task', {'goal':'same','toolsets':['web']},
                                     session_id='p',tool_call_id='old') is None
    # Hermes can emit this terminal post hook while an interrupted worker
    # is still unwinding; the worker may announce its child afterwards.
    adapter.post_tool_call_hook('delegate_task', {'goal':'same','toolsets':['web']},
                               'abandoned',session_id='p',tool_call_id='old',status=status)
    denied = adapter.pre_tool_call_hook('delegate_task', {'goal':'same'},
                                        session_id='p',tool_call_id='retry')
    assert denied and 'cancelled child goal' in denied['message']
    assert adapter.pre_tool_call_hook('delegate_task', {'goal':'distinct'},
                                     session_id='p',tool_call_id='new') is None
    adapter.on_subagent_start_hook(parent_session_id='p',child_session_id='old-child',
                                  child_goal='same',child_subagent_id='old-task')
    assert adapter.pre_tool_call_hook('read_file', {'path':'/data/secret'},
                                     session_id='old-child',task_id='old-task') is not None
    adapter.on_subagent_start_hook(parent_session_id='p',child_session_id='new-child',
                                  child_goal='distinct',child_subagent_id='new-task')
    assert adapter.pre_tool_call_hook('read_file', {'path':'/data/secret'},
                                     session_id='new-child',task_id='new-task') is None


@pytest.mark.parametrize('on_denial', ['block', 'log'])
def test_grant_rejection_publishes_only_final_denial(on_denial):
    from unittest.mock import MagicMock
    g, events = guard()
    g._on_denial = on_denial
    client = MagicMock()
    g._control_plane = client
    denied = g.pre_tool_call('delegate_task', {'goal': 'g', 'toolsets': []},
                             session_id='p', tool_call_id='reject')
    assert denied and denied['action'] == 'block'
    assert [event.decision for event in events] == ['DENY']
    client.emit_for_enforcement.assert_called_once()
    decision = client.emit_for_enforcement.call_args.args[0]
    assert not decision.allowed and decision.error_type == 'delegation_rejected'
    assert client.emit_for_enforcement.call_args.kwargs['chain_result'] is None
    g.post_tool_call('delegate_task', {}, '{}', session_id='p', tool_call_id='reject')
    assert [event.decision for event in events] == ['DENY', 'DENY']


def test_cancelled_pre_hook_cannot_stage_grants_after_post():
    g, _ = guard()
    g._finish_delegation('p', 'old', 'cancelled', {'goal': 'old-goal'})
    # The authorization worker was still computing grants at cancellation.
    denied = g._grant_children('p', [('old-goal', None)], 'old')
    assert denied and 'cancelled' in denied['message']
    assert not g._planned_children


def test_cancelled_goal_reservation_survives_session_end():
    g, _ = guard()
    assert g.pre_tool_call('delegate_task', {'goal': 'same'}, session_id='p', tool_call_id='old') is None
    g.post_tool_call('delegate_task', {'goal': 'same'}, 'cancelled',
                    session_id='p', tool_call_id='old', status='cancelled')
    g.on_session_end('p')
    denied = g.pre_tool_call('delegate_task', {'goal': 'same'}, session_id='p', tool_call_id='retry')
    assert denied and 'cancelled child goal' in denied['message']


def test_anonymous_late_child_cannot_take_a_distinct_goal_grant():
    g, _ = guard()
    g._finish_delegation('p', 'old', 'cancelled', {'goal': 'old-goal'})
    assert g.pre_tool_call('delegate_task', {'goal': 'new-goal'}, session_id='p', tool_call_id='new') is None
    g.on_subagent_start('p', 'late-child')
    assert g.pre_tool_call('read_file', {'path': '/data/x'}, session_id='late-child')
    g.on_subagent_start('p', 'new-child', child_goal='new-goal')
    assert g.pre_tool_call('read_file', {'path': '/data/x'}, session_id='new-child') is None


def test_missing_ids_block_in_gateway_without_static_warrant():
    g, events = guard()
    g.set_session_warrant('gateway', g._static_warrant, g._static_signing_key)
    g._static_warrant = None
    assert g.pre_tool_call('read_file', {'path': '/data/x'}, tool_call_id='missing')
    g.post_tool_call('read_file', {}, '{}', tool_call_id='missing')
    assert events and all(e.decision == 'DENY' for e in events)


def test_exact_capability_is_not_bypassed_by_a_broader_prefixed_alias():
    issuer, holder = SigningKey.generate(), SigningKey.generate()
    warrant = (Warrant.mint_builder().holder(holder.public_key)
               .capability('read_file', path=Subpath('/public'))
               .capability('tool:read_file', path=Subpath('/'))
               .ttl(600).mint(issuer))
    g = HermesGuard(warrant=warrant, signing_key=holder, trusted_roots=[issuer.public_key])
    assert g.pre_tool_call('read_file', {'path': '/secret'}, session_id='p')
    assert g.pre_tool_call('read_file', {'path': '/public/x'}, session_id='p') is None


def test_log_only_denied_spawn_cannot_compete_for_pending_authority():
    from tenuo import Exact
    issuer, holder = SigningKey.generate(), SigningKey.generate()
    warrant = (Warrant.mint_builder().holder(holder.public_key)
               .capability('delegate_task', goal=Wildcard(), context=Exact('approved'))
               .capability('read_file', path=Subpath('/data')).ttl(600).mint(issuer))
    g = HermesGuard(warrant=warrant, signing_key=holder, trusted_roots=[issuer.public_key], on_denial='log')
    assert g.pre_tool_call('delegate_task', {'goal': 'same', 'context': 'approved'},
                           session_id='p', tool_call_id='good') is None
    denied = g.pre_tool_call('delegate_task', {'goal': 'same', 'context': 'unapproved'},
                            session_id='p', tool_call_id='bad')
    assert denied and denied['action'] == 'block'
    g.post_tool_call('delegate_task', {'goal': 'same', 'context': 'unapproved'}, '{}',
                    session_id='p', tool_call_id='bad')
    g.on_subagent_start('p', 'authorized-child', child_goal='same')
    assert g.pre_tool_call('read_file', {'path': '/data/x'}, session_id='authorized-child') is None


@pytest.mark.parametrize('action', ['', '   ', '\t\n', ' SpAwN '])
def test_spawn_action_normalization_matches_hermes(action):
    g, _ = guard()
    args = {'action': action, 'goal': 'first'}
    assert g.pre_tool_call('delegate_task', args, session_id='p', tool_call_id='first') is None
    g.on_subagent_start('p', 'c', child_goal='first')
    assert g.pre_tool_call('read_file', {'path': '/data/x'}, session_id='c') is None
    args = {'action': action, 'goal': 'unused'}
    assert g.pre_tool_call('delegate_task', args, session_id='p', tool_call_id='second') is None
    g.post_tool_call('delegate_task', args, '{}', session_id='p', tool_call_id='second')
    g.on_subagent_start('p', 'late', child_goal='unused')
    assert g.pre_tool_call('read_file', {'path': '/data/x'}, session_id='late')


@pytest.mark.parametrize('dropped', ['tool', 'argument'])
def test_unused_invalid_plan_specs_fail_closed(tmp_path, dropped):
    import base64
    import json
    from types import SimpleNamespace
    from unittest.mock import patch
    from hermes_tenuo import register
    g, _ = guard()
    root_tools = {'read_file': {'path': {'patterns': ['^[$']}}}
    child_tools = {} if dropped == 'tool' else {'read_file': {}}
    plan = {'version': 1, 'root': {'tools': root_tools},
            'levels': [{'ttl_seconds': 60, 'tools': child_tools}]}
    path = tmp_path / 'plan.json'
    path.write_text(json.dumps(plan))
    path.chmod(0o600)
    hooks = {}
    ctx = SimpleNamespace(register_skill=lambda *a, **kw: None,
                          register_hook=lambda name, fn: hooks.setdefault(name, fn))
    with patch('hermes_tenuo._config._get_plugin_entry', return_value={
        'warrant': base64.b64encode(g._static_warrant.to_bytes()).decode(),
        'delegation_plan': str(path),
    }):
        register(ctx)
    assert hooks['pre_tool_call'](tool_name='read_file', args={})['action'] == 'block'
