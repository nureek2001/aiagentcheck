"""Allowlisted progress through a GitHub Check; never publish source or model text."""
import json
import os
import time

import httpx


class CheckTelemetry:
    def __init__(self):
        self.token = os.environ.get('GITHUB_TOKEN', '')
        self.repo = os.environ.get('GITHUB_REPOSITORY', '')
        self.sha = os.environ.get('GITHUB_SHA', '')
        self.run = os.environ.get('GITHUB_RUN_ID', '')
        self.attempt = os.environ.get('GITHUB_RUN_ATTEMPT', '1')
        self.check_id = None
        self.last = 0

    def send(self, state):
        if not self.token or not self.repo or not self.sha:
            return
        terminal = state.get('status') == 'completed'
        if not terminal and time.monotonic() - self.last < 20:
            return
        self.last = time.monotonic()
        safe = {k: state[k] for k in ('stage', 'status', 'started_at', 'updated_at', 'completed', 'total', 'exit_code') if k in state}
        requirement = str(state.get('requirement', '')).split(' ')[0]
        if requirement in {f'ИБ-{i:02}' for i in range(1, 9)} | {'EXTRA'}:
            safe['requirement'] = requirement
        safe['usage'] = {k: int(state.get('usage', {}).get(k, 0)) for k in ('requests', 'total_tokens')}
        body = {'name': 'KMG agent progress', 'head_sha': self.sha,
                'external_id': self.run + ':' + self.attempt,
                'status': 'completed' if terminal else 'in_progress',
                'output': {'title': 'KMG assessment telemetry', 'summary': 'KMG_PROGRESS_V1\n' + json.dumps(safe)}}
        if terminal:
            body['conclusion'] = 'neutral'
        try:
            with httpx.Client(timeout=5, trust_env=False) as client:
                url = f'https://api.github.com/repos/{self.repo}/check-runs'
                headers = {'Authorization': 'Bearer ' + self.token, 'Accept': 'application/vnd.github+json'}
                if self.check_id:
                    body.pop('head_sha')
                    response = client.patch(url + '/' + str(self.check_id), headers=headers, json=body)
                else:
                    response = client.post(url, headers=headers, json=body)
                if response.status_code in (200, 201):
                    self.check_id = response.json()['id']
        except (httpx.HTTPError, ValueError, KeyError):
            pass  # Monitoring failure must not change the security verdict.
