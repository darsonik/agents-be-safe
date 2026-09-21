import json
import threading
import time
import unittest
import urllib.error
import urllib.request

from app.config import Settings
from app.web.server import create_server


class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = create_server(Settings(), port=0)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.root = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def request(self, path, payload=None, headers=None):
        data = json.dumps(payload).encode() if payload is not None else None
        return urllib.request.urlopen(
            urllib.request.Request(
                self.root + path,
                data=data,
                headers=headers or ({"Content-Type": "application/json"} if data else {}),
            )
        )

    def test_ui_and_security_headers(self):
        with self.request("/") as response:
            self.assertIn(b"Start with a repository", response.read())
            self.assertIn("frame-ancestors 'none'", response.headers["Content-Security-Policy"])

    def test_cross_origin_scan_refused(self):
        with self.assertRaises(urllib.error.HTTPError) as error:
            self.request(
                "/api/scans",
                {"demo": True},
                {"Content-Type": "application/json", "Origin": "https://evil.test"},
            )
        self.assertEqual(error.exception.code, 403)
        error.exception.close()

    def test_demo_job_reaches_report(self):
        with self.request("/api/scans", {"demo": True}) as response:
            job_id = json.load(response)["id"]
        for _ in range(30):
            with self.request("/api/scans/" + job_id) as response:
                job = json.load(response)
            if job["status"] != "running":
                break
            time.sleep(0.02)
        self.assertEqual(job["status"], "completed")
        self.assertEqual(job["report"]["mode"], "demo")
        self.assertEqual(len(job["report"]["findings"]), 5)

    def test_bad_url_rejected_before_network(self):
        with self.assertRaises(urllib.error.HTTPError) as error:
            self.request("/api/scans", {"url": "http://localhost/private"})
        self.assertEqual(error.exception.code, 400)
        error.exception.close()
