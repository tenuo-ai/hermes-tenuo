"""Validate release contents before installation; run with Python 3.11+."""
import ast
import email
import tarfile
import tomllib
import zipfile
from pathlib import Path

root = Path(__file__).resolve().parents[1]
project = tomllib.loads((root / 'pyproject.toml').read_text())['project']
version = project['version']
manifest = (root / 'plugin.yaml').read_text()
assert f'version: {version}\n' in manifest
for dependency in project['dependencies']:
    assert f'"{dependency}"' in manifest, dependency
source_version = ast.literal_eval((root / 'hermes_tenuo/_version.py').read_text().split('__version__ = ')[1].strip())
assert source_version == version
locked = tomllib.loads((root / 'uv.lock').read_text())['package']
assert next(p['version'] for p in locked if p['name'] == 'hermes-tenuo') == version
with zipfile.ZipFile(root / f'dist/hermes_tenuo-{version}-py3-none-any.whl') as wheel:
    names = set(wheel.namelist())
    assert {n.split('/')[0] for n in names} == {'hermes_tenuo', f'hermes_tenuo-{version}.dist-info'}
    for path in (root / 'hermes_tenuo').rglob('*.py'):
        assert path.relative_to(root).as_posix() in names, path
    for skill in ('hands', 'tenuo-scope'):
        assert f'hermes_tenuo/skills/{skill}/SKILL.md' in names
    metadata = email.message_from_bytes(wheel.read(f'hermes_tenuo-{version}.dist-info/METADATA'))
    assert metadata['Version'] == version
    entry = wheel.read(f'hermes_tenuo-{version}.dist-info/entry_points.txt').decode()
    assert 'hermes-tenuo = hermes_tenuo.cli:main' in entry
    assert '[hermes_agent.plugins]' in entry
with tarfile.open(root / f'dist/hermes_tenuo-{version}.tar.gz') as archive:
    names = {n.split('/', 1)[1] for n in archive.getnames() if '/' in n}
    for path in ('__init__.py', 'plugin.yaml', 'tests/conftest.py', 'tests/__init__.py',
                 'docs/hands-first-session.md', 'scripts/check_release_artifacts.py'):
        assert path in names, path
print(f'Validated wheel, sdist and manifest for {version}')
