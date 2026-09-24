"""Publish reviewed edits to an isolated branch; wait for CI, then open a draft/ready PR."""
import hashlib
import json
import re
import subprocess
import time
from pathlib import Path

import httpx

from .errors import AnalysisError
from .github_sync import github_token
from .project import inspect_project
from .proposals import build_patch
from .redaction import Redactor
from .reporting import write_json


def repository_name(repo):
    remote = subprocess.check_output(['git', '-C', str(repo), 'remote', 'get-url', 'origin'], text=True).strip()
    match = re.fullmatch(r'https://github.com/([\w.-]+/[\w.-]+?)(?:\.git)?', remote)
    if not match:
        raise AnalysisError('A GitHub HTTPS origin is required')
    return match[1]


def publish(repo, proposal_dir, expected_hash, timeout=2100):
    proposal_dir = Path(proposal_dir)
    proposal = json.loads((proposal_dir / 'proposal.json').read_text(encoding='utf-8'))
    patch = (proposal_dir / 'proposal.patch').read_text(encoding='utf-8')
    if hashlib.sha256(patch.encode()).hexdigest() != expected_hash:
        raise AnalysisError('Proposal changed since preview; review again')
    if (proposal_dir / 'pr.json').exists():
        raise AnalysisError('Publication already started; inspect its status before retrying')
    token = github_token()
    if not token:
        raise AnalysisError('GitHub login required')
    redactor = Redactor([token])
    project = inspect_project(Path(repo), redactor)
    if project.commit != proposal['commit'] or project.fingerprint != proposal['source_fingerprint']:
        raise AnalysisError('Target changed since proposal; generate a fresh assessment')
    edits = proposal.get('edits', [])
    documents = {e['path']: project.documents[e['path']].text for e in edits}
    if not edits or build_patch(documents, edits) != patch:
        raise AnalysisError('Patch does not match reviewed structured edits')
    for path in documents:
        if any(part.lower() in {'tests', 'test', 'licenses'} for part in Path(path).parts) or Path(path).name.startswith('test'):
            raise AnalysisError('Publication cannot change tests or license files')
    repo_name = repository_name(repo)
    branch = 'security-fix/' + expected_hash[:12]
    operation = {'status': 'preparing', 'branch': branch, 'repository': repo_name, 'base_sha': project.commit,
                 'patch_sha256': expected_hash, 'url': None}
    def save(**values):
        operation.update(values)
        write_json(proposal_dir / 'pr.json', operation, redactor)
    with httpx.Client(timeout=30, trust_env=False, headers={'Authorization': 'Bearer ' + token,
                                                         'Accept': 'application/vnd.github+json'}) as client:
        def api(method, suffix, body=None):
            r = client.request(method, f'https://api.github.com/repos/{repo_name}/{suffix}', json=body)
            if r.status_code not in (200, 201, 202):
                raise AnalysisError(f'GitHub operation failed: HTTP {r.status_code}')
            return r.json()
        base = api('GET', '')['default_branch']
        if api('GET', 'git/ref/heads/' + base)['object']['sha'] != project.commit:
            raise AnalysisError('Remote base moved; scan the latest version first')
        save(base=base)
        try:
            blobs = []
            for path, original in documents.items():
                changes = sorted((original.index(e['before']), e) for e in edits if e['path'] == path)
                changed = original
                for start, e in reversed(changes):
                    changed = changed[:start] + e['after'] + changed[start + len(e['before']):]
                blob = api('POST', 'git/blobs', {'content': changed, 'encoding': 'utf-8'})
                blobs.append({'path': path, 'mode': '100644', 'type': 'blob', 'sha': blob['sha']})
            tree = api('POST', 'git/trees', {'base_tree': api('GET', 'git/commits/' + project.commit)['tree']['sha'], 'tree': blobs})
            commit = api('POST', 'git/commits', {'message': 'Security fix proposal: ' + proposal['finding_id'],
                                                'tree': tree['sha'], 'parents': [project.commit]})
            sha = commit['sha']
            api('POST', 'git/refs', {'ref': 'refs/heads/' + branch, 'sha': sha})
            save(status='ci_running', head_sha=sha)
            deadline = time.monotonic() + timeout
            completed = None
            while time.monotonic() < deadline:
                runs = api('GET', 'actions/runs?head_sha=' + sha + '&per_page=30')['workflow_runs']
                matching = [r for r in runs if r.get('path') == '.github/workflows/security.yml' and r['event'] == 'push']
                if matching and matching[0]['status'] == 'completed':
                    completed = matching[0]
                    break
                time.sleep(20)
            # CI must actually run tests and assessment; no silent promotion based on missing jobs.
            jobs = api('GET', f"actions/runs/{completed['id']}/jobs?per_page=100")['jobs'] if completed else []
            tests_ok = any(j['name'] == 'Product tests' and j['conclusion'] == 'success' for j in jobs)
            scan_ok = any('Required security gate' in j['name'] and j['conclusion'] == 'success' for j in jobs)
            draft = not (tests_ok and scan_ok)
            body = ('## Proposed change\n' + proposal['summary'] + '\n\n'
                    'Patch reviewed and explicitly approved in the local dashboard.\n\n'
                    f'Base: `{project.commit}`\nHead: `{sha}`\n\n'
                    f'Product tests passed: {tests_ok}. Full security gate passed: {scan_ok}.\n'
                    + ('CI: ' + completed['html_url'] if completed else 'CI did not finish before the wait limit.')
                    + '\n\n' + '\n'.join('- ' + c['path'] + ': ' + c['reason'] for c in proposal['changes'])
                    + '\n\nThis PR is never automatically merged. Review remaining findings and CI evidence.')
            pr = api('POST', 'pulls', {'title': 'Security fix: ' + proposal['finding_id'], 'head': branch,
                                      'base': base, 'body': body, 'draft': draft})
            save(status='draft_pr' if draft else 'ready_pr', url=pr['html_url'], tests_passed=tests_ok,
                 scan_passed=scan_ok, ci_url=completed['html_url'] if completed else None)
            return operation
        except Exception as exc:
            save(status='error', message=str(exc) if isinstance(exc, AnalysisError) else 'Publication failed; inspect branch before retrying')
            raise
