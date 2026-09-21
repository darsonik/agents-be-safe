import base64
import json
import os
import threading
import time
import unittest
import urllib.error
import urllib.request
from unittest.mock import patch
from http.server import ThreadingHTTPServer
from app import scanner as s
from app.server import Handler


class ScannerTests(unittest.TestCase):
    def test_repo_url_rejects_ssrf_and_ambiguous_paths(self):
        for url in ['http://github.com/a/b', 'https://127.0.0.1/a/b', 'https://github.com@evil.test/a/b',
                    'https://github.com/a/b?x=y', 'https://github.com/a/..', 'https://github.com/a/b/tree/main', None]:
            with self.subTest(url=url), self.assertRaises(s.ScanError):
                s.parse_repo(url)
        self.assertEqual(s.parse_repo('https://github.com/test/repo.git/'), 'test/repo')

    def test_redirects_are_never_followed(self):
        with self.assertRaises(s.ScanError):
            s.NoRedirect().redirect_request(None, None, 302, '', {}, 'http://127.0.0.1')

    def test_collection_pins_commit_and_skips_links_large_files(self):
        sha = 'a' * 40
        replies = [{"default_branch": "main"}, {"sha": sha}, {"tree": [
            {"type": "blob", "path": "SKILL.md", "size": 9, "sha": sha, "mode": "100644"},
            {"type": "blob", "path": "link.py", "size": 9, "sha": sha, "mode": "120000"},
            {"type": "blob", "path": "big.py", "size": 99000, "sha": sha},
            {"type": "commit", "path": "external"},
        ]}, {"encoding": "base64", "content": base64.b64encode(b'# A skill').decode()}]
        with patch.object(s, 'request_json', side_effect=replies) as request:
            result = s.collect('https://github.com/test/repo')
        self.assertEqual(len(result['files']), 1)
        self.assertEqual(len(result['skipped']), 3)
        self.assertIn(sha, request.call_args_list[2].args[0])
        self.assertEqual(result['commit'], sha)

    def test_candidate_selection_ignores_dependencies(self):
        self.assertFalse(s.candidate('node_modules/tool/index.js'))
        self.assertFalse(s.candidate('secrets.env'))
        self.assertTrue(s.candidate('.mcp.json'))
        self.assertTrue(s.candidate('.agents/skills/helper/SKILL.md'))

    def test_static_evidence_is_real_and_line_numbered(self):
        snap = s.demo_snapshot()
        findings = s.static_findings(snap['files'])
        self.assertEqual(len(findings), 5)
        for f in findings:
            source = next(x['content'] for x in snap['files'] if x['path'] == f['path'])
            self.assertIn(f['evidence'], source)
        self.assertEqual(findings[0]['line'], 2)

    def test_fabricated_model_evidence_rejected(self):
        files = s.demo_snapshot()['files']
        finding = s.static_findings(files)[0]
        finding['evidence'] = 'This is invented'
        with self.assertRaises(s.ScanError):
            s.validate_findings({'findings': [finding]}, files)

    def test_line_numbers_are_computed_not_trusted(self):
        files = s.demo_snapshot()['files']
        finding = s.static_findings(files)[0]
        finding['line'] = 999
        self.assertEqual(s.validate_findings({'findings': [finding]}, files)[0]['line'], 2)

    def test_missing_providers_never_certify_safety(self):
        snap = s.demo_snapshot()
        snap['files'] = [{'path': 'SKILL.md', 'kind': 'Skill', 'content': '# Hello'}]
        with patch.dict(os.environ, {}, clear=True):
            result = s.assess(snap)
        self.assertEqual(result['verdict'], 'Inconclusive')
        self.assertEqual(result['providers']['jev'], 'Not run')

    def test_demo_makes_no_network_calls(self):
        with patch.object(s, 'request_json') as request:
            result = s.assess(s.demo_snapshot(), 'demo')
        request.assert_not_called()
        self.assertEqual(result['mode'], 'demo')

    def test_jev_contract_and_disagreement_preserved(self):
        findings = s.static_findings(s.demo_snapshot()['files'])[:1]
        answers = {k: {'type': 'noul', 'noul': .1} for k in [*s.DIMENSIONS, 'finding_0']}
        with patch.dict(os.environ, {'TYPESAFE_API_KEY': 'fake'}), patch.object(s, 'request_json', return_value={'answers': answers, 'model': 'jev-test'}) as request:
            dimensions, model = s.jev(s.demo_snapshot()['files'], findings)
        self.assertEqual(findings[0]['verification'], 'Models disagree')
        self.assertEqual(len(dimensions), 5)
        self.assertEqual(model, 'jev-test')
        self.assertEqual(request.call_args.args[1]['questions']['finding_0']['type'], 'noul')

    def test_jev_invalid_probabilities_fail_closed(self):
        for value in [None, True, float('nan'), 1.1, -.1, '0.5']:
            answers = {k: {'type': 'noul', 'noul': value} for k in s.DIMENSIONS}
            with self.subTest(value=value), patch.dict(os.environ, {'TYPESAFE_API_KEY': 'fake'}), patch.object(s, 'request_json', return_value={'answers': answers}), self.assertRaises(s.ScanError):
                s.jev([], [])

    def test_provider_failure_retains_static_findings(self):
        with patch.dict(os.environ, {'FIREWORKS_API_KEY': 'fake', 'FIREWORKS_MODEL': 'test', 'TYPESAFE_API_KEY': 'fake'}), patch.object(s, 'request_json', side_effect=s.ScanError('Unavailable')):
            report = s.assess(s.demo_snapshot())
        self.assertEqual(len(report['findings']), 5)
        self.assertEqual(report['providers'], {'fireworks': 'Not run', 'jev': 'Not run'})

    def test_truncated_fireworks_rejected(self):
        with patch.dict(os.environ, {'FIREWORKS_API_KEY': 'fake', 'FIREWORKS_MODEL': 'test'}), patch.object(s, 'request_json', return_value={'choices': [{'finish_reason': 'length'}]}), self.assertRaises(s.ScanError):
            s.fireworks([])

    def test_fireworks_successful_contract(self):
        files = s.demo_snapshot()['files']
        finding = s.static_findings(files)[0]
        reply = {'choices': [{'finish_reason': 'stop', 'message': {'content': json.dumps({'findings': [finding]})}}]}
        with patch.dict(os.environ, {'FIREWORKS_API_KEY': 'fake', 'FIREWORKS_MODEL': 'test'}), patch.object(s, 'request_json', return_value=reply) as request:
            result = s.fireworks(files)
        self.assertEqual(result[0]['origin'], 'Fireworks')
        self.assertEqual(request.call_args.args[1]['response_format'], {'type': 'json_object'})

    def test_skipped_files_keep_report_incomplete(self):
        snap = s.demo_snapshot()
        snap['skipped'] = [{'path': 'large.py', 'reason': 'budget'}]
        with patch.dict(os.environ, {'FIREWORKS_API_KEY': 'fake', 'FIREWORKS_MODEL': 'test', 'TYPESAFE_API_KEY': 'fake'}), patch.object(s, 'fireworks', return_value=[]), patch.object(s, 'jev', return_value=({}, 'test')):
            result = s.assess(snap)
        self.assertIn('Incomplete', result['coverage_status'])


class HTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.root = f'http://127.0.0.1:{cls.server.server_port}'

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def request(self, path, payload=None, headers=None):
        data = json.dumps(payload).encode() if payload is not None else None
        return urllib.request.urlopen(urllib.request.Request(self.root + path, data=data,
            headers=headers or ({'Content-Type': 'application/json'} if data else {})))

    def test_ui_and_security_headers(self):
        with self.request('/') as response:
            self.assertIn(b'Start with a repository', response.read())
            self.assertIn("frame-ancestors 'none'", response.headers['Content-Security-Policy'])

    def test_cross_origin_scan_refused(self):
        with self.assertRaises(urllib.error.HTTPError) as error:
            self.request('/api/scans', {'demo': True}, {'Content-Type': 'application/json', 'Origin': 'https://evil.test'})
        self.assertEqual(error.exception.code, 403)
        error.exception.close()

    def test_demo_job_reaches_report(self):
        with self.request('/api/scans', {'demo': True}) as response:
            job_id = json.load(response)['id']
        for _ in range(30):
            with self.request('/api/scans/' + job_id) as response:
                job = json.load(response)
            if job['status'] != 'running':
                break
            time.sleep(.02)
        self.assertEqual(job['status'], 'completed')
        self.assertEqual(job['report']['mode'], 'demo')
        self.assertEqual(len(job['report']['findings']), 5)

    def test_bad_url_rejected_before_network(self):
        with self.assertRaises(urllib.error.HTTPError) as error:
            self.request('/api/scans', {'url': 'http://localhost/private'})
        self.assertEqual(error.exception.code, 400)
        error.exception.close()

if __name__ == '__main__':
    unittest.main()
