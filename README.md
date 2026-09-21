# Agents Be Safe

A local web application for reviewing public GitHub repositories that contain agent skills, MCP configuration, and custom tool implementations. Python 3.14+, no third-party dependencies.

## Run

```powershell
python main.py
```

Open http://127.0.0.1:8000 and choose **Explore a sample report**. The sample is fictional and runs static rules only; it never pretends to contain AI results.

For live AI assessment, set environment variables in the same terminal before starting:

```powershell
$env:FIREWORKS_API_KEY = 'your-key'
$env:FIREWORKS_MODEL = 'your-fireworks-model-or-deployment-id'
$env:TYPESAFE_API_KEY = 'your-key'
python main.py
```

Choose a Fireworks model that supports chat completions and JSON mode, with enough context for up to 180 KB of source plus the response. `TYPESAFE_MODEL` defaults to `jev-latest`. An optional `GITHUB_TOKEN` increases GitHub's API allowance. `PORT` defaults to 8000. `.env.example` documents settings; `.env` files are not loaded automatically. Never place credentials in browser code or commit them.

## How assessment works

1. Validate a canonical `https://github.com/owner/repository` URL. Resolve the default branch to an immutable commit and fetch its tree and blobs via the GitHub API. Redirects are refused.
2. Prioritize SKILL.md and MCP-related paths, then supporting source. Inspect at most 40 UTF-8 files, 24 KB each, 180 KB total. No cloning, installs, subprocesses, imports, or MCP calls occur. Symlinks and submodules are not followed.
3. Static rules identify suspicious patterns. Fireworks reasons over the selected source and proposes findings with exact evidence and remediation. The application verifies that cited paths and quotes exist and computes line numbers itself. Invalid or truncated model responses mark that provider unavailable.
4. Jev answers independent Noul questions about five risk dimensions and each finding's support in context. Probabilities at or above 0.8 label a finding supported; at or below 0.2 label disagreement; other values need review. These are provisional, uncalibrated thresholds, not exploit probabilities or proof of correctness. Findings are retained even when models disagree.
5. The report includes the pinned commit, evidence links, engine status, probabilities, findings, coverage gaps, and remediation. Export JSON, Markdown, or use the browser's Print / PDF option.

Prompt injection, data exfiltration, command execution, excessive access, and supply-chain trust are the initial categories. A high/critical finding or any Jev risk probability >= 0.8 produces “High risk indicators.” Other findings require review. An empty report with missing engines or incomplete collection is “Inconclusive.” Even a completed scan never certifies a repository as safe.

## Scope and deployment

This is a **local MVP**, bound to loopback, not a production multi-user service. The UI checks same-origin requests; credentials stay on the server; reports render as text under a restrictive content security policy. Two scans may run concurrently. Reports live in memory, are lost on restart, and older completed reports are pruned on new scans (one-hour age and roughly 20-report count limits).

Only public GitHub repositories are supported. Selected source is shared with Fireworks and TypeSafe. External packages, remote MCP implementations, dependencies, generated/vendor files, unsupported file formats, and runtime behavior are outside the assessment. Referenced skill assets can be omitted by the selection budget. The coverage panel lists selected and skipped candidate files, but candidate coverage is not whole-repository coverage. Static patterns can flag harmless documentation; AI analysis can miss or invent risks despite evidence checks. Review high-impact conclusions manually.

Before hosting for other users, add authentication, per-user report isolation, quotas and billing controls, a production HTTP server and job queue, retention policies, and validated security evaluation datasets. Runtime inspection of third-party servers would require a separate isolated analysis service.

## Verify

```powershell
python -m unittest discover -s tests -v
```

Tests use mocked GitHub/model responses, plus real local HTTP requests. Paid provider calls require configured credentials and are not part of offline tests.

Integration references: [Fireworks chat completions](https://docs.fireworks.ai/api-reference/post-chatcompletions), [TypeSafe HTTP API](https://docs.typesafe.ai/api), [Noul judgments](https://docs.typesafe.ai/primitives/noul), [citation checking pattern](https://docs.typesafe.ai/cookbooks/citation_check).
