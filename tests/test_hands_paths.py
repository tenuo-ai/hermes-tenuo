"""The shared path-jail library validates actual device filesystem paths."""
import os
from pathlib import Path

import pytest
from path_jail import Jail

from hermes_tenuo.hands import device, wire
from hermes_tenuo.hands.paths import workspace
from tests import test_hands as shared

hub = shared.hub
folder = shared.folder
paired = shared.paired
_no_inherited_proxy = shared._no_inherited_proxy


def signed_at(hub, paired, path):
    job = shared._job(hub, paired, dir=str(path))
    args = {'dir': job['dir'], 'cmd': wire.digest(job['id'], job['cmd'], False, None, 30, '', 0, '')}
    job['pop'] = wire.sign(hub.pick(paired.name).grant, hub.key, wire.TOOL, args)
    return job


def test_setup_resolves_explicit_workspace_link(tmp_path, folder):
    alias = tmp_path / 'chosen-project'
    alias.symlink_to(folder, target_is_directory=True)
    jail = workspace(str(alias))
    assert isinstance(jail, Jail)
    assert jail.root == str(folder.resolve())


@pytest.mark.parametrize('kind', ['missing', 'file', 'broken-link'])
def test_setup_rejects_unusable_workspace(tmp_path, kind):
    path = tmp_path / kind
    if kind == 'file':
        path.write_text('not a directory')
    elif kind == 'broken-link':
        path.symlink_to(tmp_path / 'missing-target')
    with pytest.raises(ValueError, match='not a folder'):
        workspace(str(path))


def test_signed_nested_command_is_accepted(hub, paired):
    path = Path(paired.folder) / 'src'
    assert paired.verify(signed_at(hub, paired, path)) == str(path)


@pytest.mark.parametrize('kind', ['outside-link', 'broken-link', 'inside-link', 'file', 'missing'])
def test_signed_path_does_not_bypass_filesystem_checks(hub, paired, tmp_path, kind):
    path = Path(paired.folder) / kind
    if kind == 'outside-link':
        external = tmp_path / 'external'
        external.mkdir()
        path.symlink_to(external, target_is_directory=True)
    elif kind == 'inside-link':
        path.symlink_to(Path(paired.folder) / 'src', target_is_directory=True)
    elif kind == 'broken-link':
        path.symlink_to(tmp_path / 'missing-target')
    elif kind == 'file':
        path.write_text('not a directory')
    with pytest.raises(device.HandsError):
        paired.verify(signed_at(hub, paired, path))
    assert 'job-1' not in paired._seen


def test_replaced_workspace_link_does_not_move_authority(hub, paired, tmp_path):
    root = Path(paired.folder)
    job = signed_at(hub, paired, root)
    root.rename(root.with_name('original-project'))
    external = tmp_path / 'external'
    external.mkdir()
    root.symlink_to(external, target_is_directory=True)
    with pytest.raises(device.HandsError):
        paired.verify(job)


def test_jail_rejects_prefix_sibling(folder):
    sibling = folder.with_name(folder.name + '-other')
    sibling.mkdir()
    with pytest.raises(ValueError):
        workspace(str(folder)).contains(os.path.realpath(sibling))
