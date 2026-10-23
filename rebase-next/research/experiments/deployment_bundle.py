import hashlib
import json
from pathlib import Path
import subprocess
import sys
import urllib.request
import uuid

package = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(package / 'tools'))
import client
import capacity
import harness
import invoicing
from harness import Backend, command, require

for module in (client, capacity, harness, invoicing):
    require(Path(module.__file__).resolve().is_relative_to(package / 'tools'), 'Original checkout module imported')
destination = package / 'target/template-deployment'
destination.mkdir(mode=0o700)
manifest = json.loads((package / 'BUNDLE.json').read_text())
template = json.loads((package / 'deploy/server.example.json').read_text())
binary = package / 'bin/rebase-next'
report = {'status': 'passed', 'tool_imports': {module.__name__: str(Path(module.__file__).resolve())
          for module in (client, capacity, harness, invoicing)}, 'models': []}


def values(backend, model, catalog, ids):
    identity = catalog['model']
    def total(owner, slot):
        return backend.call('roots.read', {'model': identity, 'owner': owner, 'slot': slot,
                                           'read': {'kind': 'summary'}})['value']['sum']
    if model == 'calculation':
        account = next(c for c in catalog['contracts'] if c['name'] == 'Account')
        slot = next(r['slot'] for r in account['roots'] if r['name'] == 'history')
        actual = {name: total(ids[name], slot) for name in ('A', 'Left', 'Right', 'Final')}
        require(actual == {'A': '30', 'Left': '60', 'Right': '90', 'Final': '150'}, 'Calculation template values')
    elif model == 'equipment':
        actual = {name: backend.call('records.get', {'model': identity, 'id': ids[name]})['derived']['allocated']
                  for name in ('a', 'b')}
        require(actual == {'a': '8', 'b': '2'}, 'Equipment template allocations')
        require(total(ids['pool'], 7) == '10', 'Equipment template availability')
    else:
        actual = {name: total(ids['Invoice'], slot) for slot, name in
                  ((13, 'gross'), (21, 'paid'), (23, 'balance'), (29, 'receivable'), (31, 'payable'))}
        actual.update(cash=total(ids['Treasury'], 37), refund_capacity=total(ids['Payment'], 41))
        require(actual == {'gross': '9244', 'paid': '9244', 'balance': '0', 'receivable': '13866',
                           'payable': '13866', 'cash': '9244', 'refund_capacity': '9244'}, 'Invoicing template values')
    return actual


for model, fixture in (('calculation', 'causal-diamond'), ('equipment', 'equipment'), ('invoicing', 'invoice-refund')):
    backend = Backend(binary, destination / model, model)
    try:
        config = json.loads(json.dumps(template))
        config['listen'] = '127.0.0.1:0'
        public = command('openssl', 'pkey', '-in', backend.private, '-pubout').decode()
        require(public != (package / 'tests/fixtures/test-ed25519-public.pem').read_text(), 'Fixture issuer reused')
        config['identity']['public_keys']['main'] = public
        backend.config = config
        backend.config_path.write_bytes(client._bytes(config))
        request = backend.directory / 'token-request.json'
        request.write_bytes(client._bytes({'tenant': backend.tenant, 'actor': backend.actor,
                                          'epoch': 0, 'ttl': 300, 'key_id': 'main'}))
        backend.token = command(binary, 'auth', 'issue', backend.config_path, request, backend.private).decode().strip()
        backend.token_path.write_text(backend.token + '\n')
        backend.start()
        with urllib.request.urlopen(backend.url.removesuffix('/rpc') + '/health', timeout=10) as response:
            require(response.status == 200, 'Template service health')
        session = client.loads(command(sys.executable, package / 'tools/client.py', '--url', backend.url,
                                       '--token-file', backend.token_path, 'call', 'session.describe'))
        require('operation_context' in session, 'Authenticated template session missing context')
        catalog = backend.call('model.describe', {})
        require(catalog['model'] == manifest['models'][model]['model'], 'Template model identity')
        draft = backend.cli('fixture', 'plan', fixture, '--namespace', str(uuid.uuid4()))
        plan = backend.plan(draft, 'fixture')
        outcome = client.execute(backend.url, backend.token, plan)
        require(outcome['status'] == 'committed', 'Template fixture commit')
        initial = values(backend, model, catalog, draft['fixture']['ids'])
        backend.stop()
        checked = backend.cli('check', backend.store)
        require(checked['status'] == 'valid', 'Template store integrity')
        backup = backend.directory / 'verified-backup.json'
        backend.cli('backup', backend.store, backup)
        bad = json.loads(backup.read_text())
        bad['sha256'] = '0' * 64
        damaged = backend.directory / 'damaged-backup.json'
        damaged.write_text(json.dumps(bad))
        failures = []
        for name, selected, source, expected in (
            ('damaged', model, damaged, 'invalid_input'),
            ('wrong-model', 'equipment' if model == 'calculation' else 'calculation', backup, 'model_mismatch')):
            target = backend.directory / (name + '.redb')
            rejected = subprocess.run([str(binary), '--model', selected, 'restore', str(source), str(target)],
                                      cwd=package, capture_output=True, text=True)
            require(rejected.returncode != 0 and rejected.stderr.startswith(expected + ':'), name + ' restore verdict')
            require(not target.exists() and not list(backend.directory.glob('.rebase-*.tmp')), name + ' restore leaked files')
            failures.append({'case': name, 'error': expected, 'destination_absent': True, 'temporary_files_absent': True})
        restored = backend.directory / 'restored.redb'
        backend.cli('restore', backup, restored)
        before = restored.read_bytes()
        rejected = subprocess.run([str(binary), '--model', model, 'restore', str(backup), str(restored)],
                                  cwd=package, capture_output=True, text=True)
        require(rejected.returncode != 0 and rejected.stderr.startswith('storage:'), 'Existing restore target verdict')
        require(restored.read_bytes() == before and not list(backend.directory.glob('.rebase-*.tmp')),
                'Existing destination changed or temporary file leaked')
        failures.append({'case': 'existing-destination', 'error': 'storage', 'physical_bytes_unchanged': True,
                         'temporary_files_absent': True})
        backend.store = restored
        backend.start()
        require(values(backend, model, catalog, draft['fixture']['ids']) == initial, 'Restored template arithmetic')
        replay = client.execute(backend.url, backend.token, plan)
        require(replay['replayed'] and replay['result'] == outcome['result'], 'Restored template receipt replay')
        backend.stop()
        report['models'].append({'model': model, 'fixture': fixture, 'fresh_issuer': True,
                                 'packaged_template': True, 'authenticated_cli_readiness': True,
                                 'values': initial, 'integrity': checked, 'recovery_rejections': failures,
                                 'restored_http_values': True, 'restored_receipt_replay': True,
                                 'owned_server_stopped': backend.process is None})
    finally:
        backend.stop()
report['binary_sha256'] = hashlib.sha256(binary.read_bytes()).hexdigest()
(destination / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report, indent=2))
