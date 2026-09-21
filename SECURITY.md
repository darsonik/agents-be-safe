# Security Policy

## Supported Versions

Only the latest release and the current `master` branch receive security updates and fixes.

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x / `master` | :white_check_mark: |
| < 0.1.0 | :x:                |

---

## Repository & Contribution Security Rules

To protect the integrity of the codebase and prevent supply-chain tampering:

1. **Branch Protection Enforced:** Direct pushes (`git push origin master`) to the default branch (`master`) are strictly prohibited and blocked by repository protection rules.
2. **Pull Request Workflow:** All code modifications, bug fixes, and security patches must be submitted through a feature branch or fork and merged via a Pull Request.
3. **Protected History:** Force pushes (`git push --force`) and branch deletions on protected branches are permanently blocked.
4. **Code Review & Audit:** Every pull request is subject to review and verification prior to merging.

---

## Secrets & Credentials Policy

- **No Secrets in Source:** API keys, tokens, passwords, private certificates, or confidential endpoints must **never** be committed to the repository.
- **Environment Isolation:** Local `.env` and credential files are strictly ignored via `.gitignore`. Always use `.env.example` with empty template values for documenting configuration.
- **In-Memory Redaction:** Application settings and provider clients intentionally mask credentials in representations (`repr=False`) to prevent unintentional disclosure in logs or exception messages.

---

## Reporting a Vulnerability

If you discover a security vulnerability or potential threat in **Agents Be Safe**, please report it privately. **Do not open public GitHub issues or discussions for security vulnerabilities.**

### How to Report

Please email your report directly to:

- **Contact:** [tuhinkarmakar98@outlook.com](mailto:tuhinkarmakar98@outlook.com)
- **Subject:** `[SECURITY] agents-be-safe: <Brief Description>`

### What to Include in Your Report

To help us investigate and triage the issue quickly, please include:

1. **Description:** A detailed explanation of the issue, vulnerability type, and potential impact.
2. **Reproduction Steps:** Step-by-step instructions to reproduce the behavior.
3. **Proof of Concept:** A minimal reproducible example, payload, or script (if applicable).
4. **Environment:** OS, Python version, and any relevant configuration details.
5. **Mitigation:** Any suggestions for remediation or patches (if known).

---

## Response & Disclosure Process

1. **Acknowledgment:** You will receive an acknowledgment of your report within **48 hours**.
2. **Assessment:** We will validate and assess the severity and impact of the vulnerability.
3. **Remediation:** We will develop, test, and release a fix in a timely manner.
4. **Coordinated Disclosure:** We kindly request that you maintain confidentiality until an official fix or advisory has been published. Credit will gladly be attributed to the reporter upon release.

---

## Security Architecture & Boundaries

**Agents Be Safe** is designed as a local, read-only analysis tool with explicit security boundaries:

- **Local Loopback Binding:** The application server binds exclusively to `127.0.0.1` by default and is not intended to be exposed directly to the public internet without an external authentication reverse proxy.
- **Read-Only Analysis:** Untrusted repositories are inspected strictly via text, AST, and JSON API payloads. The scanner never clones, executes, imports, or installs code from target repositories.
- **SSRF Prevention:** Repository ingestion enforces strict URL validation against canonical GitHub repository endpoints (`https://github.com/owner/repo`) and refuses HTTP redirects.
- **Credential Protection:** API keys (`FIREWORKS_API_KEY`, `TYPESAFE_API_KEY`, `GITHUB_TOKEN`) are retained solely in server configuration memory and are never exposed to client-side browsers.

### Out of Scope

The following are considered out of scope for security reports:
- Attacks requiring physical access to the local machine or pre-existing arbitrary code execution privileges on the host.
- Issues caused by deliberately exposing the local development server (`main.py`) to untrusted networks without authentication.
- Model classification inaccuracies or heuristic evasion by adversarial prompt content, which are limitations of AI-assisted heuristics rather than software vulnerabilities.

---

## Commercial Licensing Compliance

This project is governed by a **Source-Available Non-Commercial License** ([LICENSE](LICENSE)):
- **Personal & Non-Commercial Use:** Free to use, modify, and distribute.
- **Commercial Use:** Any commercial use (hosted services, SaaS, embedding in commercial products, enterprise deployment) requires **prior written authorization** and an agreed **royalty arrangement**.
- **Commercial Inquiries:** Contact [tuhinkarmakar98@outlook.com](mailto:tuhinkarmakar98@outlook.com) to discuss licensing agreements before any commercial deployment.
