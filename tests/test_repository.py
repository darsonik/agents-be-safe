import base64
import unittest
from unittest.mock import patch

from app import http_client
from app.errors import ScanError
from app.scanning.repository import candidate, collect, parse_repo


class RepositoryTests(unittest.TestCase):
    def test_repo_url_rejects_ssrf_and_ambiguous_paths(self):
        for url in [
            "http://github.com/a/b",
            "https://127.0.0.1/a/b",
            "https://github.com@evil.test/a/b",
            "https://github.com/a/b?x=y",
            "https://github.com/a/..",
            "https://github.com/a/b/tree/main",
            None,
        ]:
            with self.subTest(url=url), self.assertRaises(ScanError):
                parse_repo(url)
        self.assertEqual(parse_repo("https://github.com/test/repo.git/"), "test/repo")

    def test_collection_pins_commit_and_skips_links_large_files(self):
        sha = "a" * 40
        replies = [
            {"default_branch": "main"},
            {"sha": sha},
            {
                "tree": [
                    {
                        "type": "blob",
                        "path": "SKILL.md",
                        "size": 9,
                        "sha": sha,
                        "mode": "100644",
                    },
                    {
                        "type": "blob",
                        "path": "skills/link.py",
                        "size": 9,
                        "sha": sha,
                        "mode": "120000",
                    },
                    {"type": "blob", "path": "skills/big.py", "size": 99000, "sha": sha},
                    {"type": "commit", "path": "external"},
                ]
            },
            {"encoding": "base64", "content": base64.b64encode(b"# A skill").decode()},
        ]
        with patch.object(http_client, "request_json", side_effect=replies) as request:
            result = collect("https://github.com/test/repo")
        self.assertEqual(len(result["files"]), 1)
        self.assertEqual(len(result["skipped"]), 3)
        self.assertIn(sha, request.call_args_list[2].args[0])
        self.assertEqual(result["commit"], sha)

    def test_candidate_selection_ignores_dependencies(self):
        self.assertFalse(candidate("node_modules/tool/index.js"))
        self.assertFalse(candidate("secrets.env"))
        self.assertTrue(candidate(".mcp.json"))
        self.assertTrue(candidate(".agents/skills/helper/SKILL.md"))
        self.assertTrue(candidate("agents/worker.py"))
        self.assertTrue(candidate("AGENTS.md"))
        self.assertTrue(candidate(".cursorrules"))
        self.assertFalse(candidate("src/database.py"))
        self.assertFalse(candidate("tests/test_sql.py"))
        self.assertFalse(candidate("README.md"))
        self.assertFalse(candidate("benchmarks/run.py"))
