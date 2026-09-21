"""Read-only, commit-pinned collection from public GitHub repositories."""

import base64
import re
import urllib.parse

from app import http_client
from app.config import Settings
from app.errors import ScanError
from app.models import Progress, Snapshot, ignore_progress


def parse_repo(value):
    if not isinstance(value, str) or len(value) > 300:
        raise ScanError("Enter a public GitHub repository URL.")
    match = re.fullmatch(
        r"https://github\.com/([A-Za-z0-9][A-Za-z0-9-]{0,38})/([A-Za-z0-9_.-]{1,100})/?",
        value.strip(),
    )
    if not match:
        raise ScanError(
            "Use https://github.com/owner/repository without branch paths or query parameters."
        )
    owner, repo = match.groups()
    repo = repo.removesuffix(".git")
    if repo in ("", ".", ".."):
        raise ScanError("Invalid repository name.")
    return owner + "/" + repo


def file_kind(path):
    lower = path.lower()
    if lower.endswith("skill.md"):
        return "Skill"
    if "mcp" in lower or lower.endswith(("claude_desktop_config.json", "settings.json")):
        return "MCP / configuration"
    return "Supporting source"


def candidate(path):
    lower = path.lower()
    if any(
        p in lower.split("/") for p in ("node_modules", ".git", "vendor", "dist", ".venv", "build")
    ):
        return False
    return lower.endswith(
        (
            ".md",
            ".py",
            ".js",
            ".ts",
            ".tsx",
            ".mjs",
            ".cjs",
            ".json",
            ".toml",
            ".yaml",
            ".yml",
            ".sh",
            ".ps1",
            ".go",
            ".rs",
        )
    )


def collect(
    repo_url: str,
    progress: Progress = ignore_progress,
    *,
    settings: Settings | None = None,
) -> Snapshot:
    settings = settings if settings is not None else Settings.from_env()
    repo = parse_repo(repo_url)
    root = "https://api.github.com/repos/" + repo

    def get(suffix):
        return http_client.request_json(root + suffix, token=settings.github_token)

    progress("Resolving repository and pinning commit")
    meta = get("")
    if meta.get("private"):
        raise ScanError("This version accepts public repositories only.")
    commit = get("/commits/" + urllib.parse.quote(meta["default_branch"], safe=""))["sha"]
    if not re.fullmatch(r"[a-f0-9]{40}", commit):
        raise ScanError("Invalid commit identifier.")
    tree = get("/git/trees/" + commit + "?recursive=1")
    entries = tree.get("tree", [])
    selected = sorted(
        [e for e in entries if e.get("type") == "blob" and candidate(e["path"])],
        key=lambda e: (
            file_kind(e["path"]) == "Supporting source",
            not e["path"].lower().endswith("skill.md"),
            e["path"],
        ),
    )
    files, skipped, total = [], [], 0
    for entry in selected:
        path = entry["path"]
        if entry.get("mode") == "120000":
            skipped.append({"path": path, "reason": "Symbolic link not followed"})
            continue
        if (
            len(files) >= settings.max_files
            or entry.get("size", settings.max_file_bytes + 1) > settings.max_file_bytes
            or total + entry.get("size", 0) > settings.max_total_bytes
        ):
            skipped.append({"path": path, "reason": "Scan size budget"})
            continue
        progress(f"Reading file {len(files) + 1} of up to {min(len(selected), settings.max_files)}")
        try:
            sha = entry.get("sha", "")
            if not re.fullmatch(r"[a-f0-9]{40}", sha):
                raise ScanError("Invalid blob identifier")
            blob = get("/git/blobs/" + sha)
            if blob.get("encoding") != "base64":
                raise ScanError("Unsupported blob encoding")
            raw = base64.b64decode(blob["content"])
            if len(raw) > settings.max_file_bytes or total + len(raw) > settings.max_total_bytes:
                raise ScanError("File exceeds size budget")
            content = raw.decode("utf-8")
            if "\x00" in content:
                raise ScanError("Binary content")
            files.append({"path": path, "content": content, "kind": file_kind(path)})
            total += len(raw)
        except (ScanError, UnicodeError, ValueError, KeyError) as exc:
            skipped.append({"path": path, "reason": str(exc)})
    skipped.extend(
        {"path": e["path"], "reason": "Submodule not inspected"}
        for e in entries
        if e.get("type") == "commit"
    )
    return {
        "repository": repo,
        "commit": commit,
        "files": files,
        "skipped": skipped,
        "tree_truncated": bool(tree.get("truncated")),
        "candidate_count": len(selected),
    }
