import time
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json

import httpx
import pytest

from kmg_agent.benchmark import score
from kmg_agent.client import DeepSeek
from kmg_agent.config import Settings
from kmg_agent.contracts import MAP
from kmg_agent.errors import BudgetError, AnalysisError
from kmg_agent.redaction import Redactor
from kmg_agent.pull_requests import publish


def test_budget_prevents_network_and_counts_concurrent_reservations():
    settings = Settings(key='fixture', max_tokens=40000, max_requests=2)
    client = DeepSeek(settings, Redactor(), time.monotonic() + 20,
                      transport=httpx.MockTransport(lambda _: pytest.fail('No network expected')))
    body = {'messages': [{'content': 'a'}], 'max_tokens': 16000}
    with ThreadPoolExecutor(max_workers=2) as pool:
        amounts = list(pool.map(lambda _: client.reserve(body), range(2)))
    with pytest.raises(BudgetError):
        client.reserve(body)
    assert client.budget()['reserved_tokens'] == sum(amounts)
    client.settle(amounts[0], 20)
    client.settle(amounts[1])
    assert client.budget()['charged_or_estimated_tokens'] == 20 + amounts[1]


def test_token_budget_stops_before_first_attempt():
    client = DeepSeek(Settings(key='fixture', max_tokens=1000), Redactor(), time.monotonic() + 20,
                      transport=httpx.MockTransport(lambda _: pytest.fail('No request allowed')))
    with pytest.raises(BudgetError):
        client.ask('x', {}, MAP)
    assert client.usage['requests'] == 0


def test_failed_network_attempt_consumes_conservative_budget():
    def fail(_):
        raise httpx.ConnectError('fixture')
    client = DeepSeek(Settings(key='fixture', retries=0), Redactor(), time.monotonic() + 20,
                      transport=httpx.MockTransport(fail))
    with pytest.raises(Exception):
        client.ask('x', {}, MAP)
    budget = client.budget()
    assert budget['attempts'] == 1 and budget['charged_or_estimated_tokens'] > 16000
    assert budget['reserved_tokens'] == 0


def test_eval_metrics_do_not_count_errors_as_true_negatives():
    rows = [{'expected': True, 'actual': True}, {'expected': False, 'actual': True},
            {'expected': True, 'actual': False}, {'expected': False, 'actual': None}]
    assert score(rows) == {'tp': 1, 'fp': 1, 'fn': 1, 'tn': 0, 'errors': 1, 'precision': .5, 'recall': .5}


def test_publish_rejects_modified_preview_before_network(tmp_path):
    (tmp_path / 'proposal.json').write_text('{}')
    (tmp_path / 'proposal.patch').write_text('changed')
    with pytest.raises(AnalysisError, match='changed since preview'):
        publish(tmp_path, tmp_path, hashlib.sha256(b'original').hexdigest())


def test_publish_does_not_duplicate_started_operation(tmp_path):
    (tmp_path / 'proposal.json').write_text('{}')
    (tmp_path / 'proposal.patch').write_text('fixture')
    (tmp_path / 'pr.json').write_text('{"status":"ci_running"}')
    with pytest.raises(AnalysisError, match='already started'):
        publish(tmp_path, tmp_path, hashlib.sha256(b'fixture').hexdigest())


def test_telemetry_excludes_source_and_model_text(monkeypatch):
    from kmg_agent.telemetry import CheckTelemetry
    for key, value in {'GITHUB_TOKEN': 'fixture-token', 'GITHUB_REPOSITORY': 'team/repo',
                       'GITHUB_SHA': 'a' * 40, 'GITHUB_RUN_ID': '123'}.items():
        monkeypatch.setenv(key, value)
    bodies = []
    real_client = httpx.Client
    def response(request):
        bodies.append(json.loads(request.content))
        return httpx.Response(201, json={'id': 1})
    monkeypatch.setattr('kmg_agent.telemetry.httpx.Client', lambda **kw: real_client(transport=httpx.MockTransport(response), **kw))
    CheckTelemetry().send({'stage': 'map', 'status': 'running', 'completed': 3, 'total': 10,
                          'message': 'SECRET-SOURCE', 'source': 'SECRET-SOURCE'})
    assert 'SECRET-SOURCE' not in json.dumps(bodies)
    assert '"completed": 3' in bodies[0]['output']['summary']

@pytest.mark.parametrize('checks_pass,draft', [(True, False), (False, True)])
def test_publish_isolated_branch_then_ci_then_pr(repo, tmp_path, monkeypatch, checks_pass, draft):
    from kmg_agent.project import inspect_project
    from kmg_agent.proposals import build_patch
    import subprocess
    project = inspect_project(repo, Redactor())
    subprocess.run(['git', '-C', str(repo), 'remote', 'add', 'origin', 'https://github.com/team/product.git'], check=True)
    original = project.documents['app.py'].text.replace('\r\n', '\n')
    edits = [{'path': 'app.py', 'before': "'administrator'", 'after': "'admin'", 'reason': 'Synthetic edit only'}]
    patch = build_patch({'app.py': original}, edits)
    output = tmp_path / 'proposal'
    output.mkdir()
    (output / 'proposal.patch').write_text(patch, encoding='utf-8', newline='\n')
    (output / 'proposal.json').write_text(json.dumps({'commit': project.commit, 'source_fingerprint': project.fingerprint,
        'edits': edits, 'finding_id': 'fixture', 'summary': 'Synthetic test', 'changes': [{'path': 'app.py', 'reason': 'fixture'}]}))
    calls = []
    def api(request):
        calls.append((request.method, request.url.path))
        path = request.url.path
        if path.endswith('/team/product'):
            result = {'default_branch': 'main'}
        elif '/git/ref/heads/' in path:
            result = {'object': {'sha': project.commit}}
        elif '/git/commits/' in path:
            result = {'tree': {'sha': 'base-tree'}}
        elif path.endswith('/git/commits'):
            result = {'sha': 'a' * 40}
        elif path.endswith('/git/refs'):
            result = {}
        elif path.endswith('/actions/runs'):
            result = {'workflow_runs': [{'id': 12, 'status': 'completed', 'path': '.github/workflows/security.yml', 'event': 'push', 'html_url': 'https://github.com/team/product/actions/runs/12'}]}
        elif path.endswith('/jobs'):
            result = {'jobs': [{'name': n, 'conclusion': 'success' if checks_pass else 'failure'} for n in ['Product tests', 'security / Required security gate']]}
        elif path.endswith('/pulls'):
            assert json.loads(request.content)['draft'] == draft
            assert any(p.endswith('/jobs') for _, p in calls)
            result = {'html_url': 'https://github.com/team/product/pull/1'}
        else:
            result = {'sha': 'fixture-tree-or-blob'}
        return httpx.Response(200, json=result)
    monkeypatch.setattr('kmg_agent.pull_requests.github_token', lambda: 'fixture-token')
    real = httpx.Client
    monkeypatch.setattr('kmg_agent.pull_requests.httpx.Client', lambda **kw: real(transport=httpx.MockTransport(api), **kw))
    result = publish(repo, output, hashlib.sha256(patch.encode()).hexdigest())
    assert result['status'] == ('draft_pr' if draft else 'ready_pr')
    assert (repo / 'app.py').read_text() == original
    assert inspect_project(repo, Redactor()).commit == project.commit
