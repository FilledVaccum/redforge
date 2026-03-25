# RedForge — Research & Decision Log
> This file captures key decisions, findings, and rationale during the build.
> Append-only — never delete entries. Newest entries at the top of each section.

---

## Tool Landscape Analysis

> Fill in during Phase 0 as each repo is read.

### promptfoo/promptfoo
- **License:** MIT
- **Architecture pattern:**
- **What to adopt conceptually:**
- **What to avoid:**
- **Probe/attack design:**
- **Notes:**

### NVIDIA/garak
- **License:** Apache 2.0
- **Architecture pattern:**
- **What to adopt conceptually:**
- **What to avoid:**
- **Probe/attack design:**
- **Notes:**

### Giskard-AI/giskard-oss
- **License:** Apache 2.0
- **Architecture pattern:**
- **What to adopt conceptually:**
- **What to avoid:**
- **Probe/attack design:**
- **Notes:**

### microsoft/PyRIT
- **License:** MIT
- **Architecture pattern:**
- **What to adopt conceptually:**
- **What to avoid:**
- **Probe/attack design:**
- **Notes:**

### protectai/llm-guard
- **License:** MIT
- **Architecture pattern:**
- **What to adopt conceptually:**
- **What to avoid:**
- **Probe/attack design:**
- **Notes:**

### cyberark/FuzzyAI
- **License:** Apache 2.0
- **Architecture pattern:**
- **What to adopt conceptually:**
- **What to avoid:**
- **Probe/attack design:**
- **Notes:**

### msoedov/agentic_security
- **License:** MIT
- **Architecture pattern:**
- **What to adopt conceptually:**
- **What to avoid:**
- **Probe/attack design:**
- **Notes:**

### EasyJailbreak/EasyJailbreak
- **License:** MIT
- **Architecture pattern:**
- **What to adopt conceptually:**
- **What to avoid:**
- **Probe/attack design:**
- **Notes:**

---

## Dependency Decisions

> Record every approved dependency, its license, and why it was chosen over alternatives.

| Package | Version | License | Purpose | Alternatives Considered |
|---------|---------|---------|---------|------------------------|
| typer | latest | MIT | CLI framework | click (also MIT, typer wraps it) |
| fastapi | latest | MIT | REST API | flask (too minimal for async) |
| uvicorn | latest | BSD-3 | ASGI server | gunicorn (less async-native) |
| httpx | latest | BSD-3 | Async HTTP client for adapters | requests (sync only) |
| pydantic | v2 | MIT | Data validation | attrs (less ecosystem support) |
| slowapi | latest | MIT | API rate limiting | — |
| python-dotenv | latest | BSD-3 | .env loading | — |
| rich | latest | MIT | CLI output formatting | — |
| pytest | latest | MIT | Testing | — |
| ruff | latest | MIT | Linting + formatting | flake8+black (slower, two tools) |
| mypy | latest | MIT | Type checking | pyright (less mature ecosystem) |
| pip-audit | latest | Apache 2.0 | CVE scanning | safety (GPL) |
| pip-licenses | latest | MIT | License compliance checking | — |
| detect-secrets | latest | Apache 2.0 | Secret scanning | — |

---

## Architecture Decisions

> Record significant architecture choices and the rationale.

### ADR-001: Adapter Pattern for Model Providers
- **Decision:**
- **Rationale:**
- **Alternatives considered:**
- **Date:**

### ADR-002: Probe Plugin Architecture
- **Decision:**
- **Rationale:**
- **Alternatives considered:**
- **Date:**

### ADR-003: Result Storage Format
- **Decision:**
- **Rationale:**
- **Alternatives considered:**
- **Date:**

### ADR-004: Authentication Strategy for REST API
- **Decision:**
- **Rationale:**
- **Alternatives considered:**
- **Date:**

---

## Security Decisions

> Record security-relevant decisions and why they were made.

### SEC-001: No eval() on model responses
- **Policy:** All model responses are strings, parsed only with explicit parsers. Never passed to eval(), exec(), or subprocess.
- **Rationale:** Model output is untrusted. Prompt injection could attempt to escape the tool.
- **Enforcement:** Grep in CI + code review checklist

### SEC-002: API keys never in logs
- **Policy:** All key material masked as `***` in logs. Keys loaded only from env vars.
- **Rationale:** Log aggregation systems (CloudWatch, Splunk) should never capture credentials.
- **Enforcement:** `secrets.py` utility wraps all key access; detect-secrets in pre-commit

### SEC-003: Scan result file permissions
- **Policy:** All result files created with `os.chmod(path, 0o600)`.
- **Rationale:** Scan results may contain sensitive model outputs or system prompt excerpts.
- **Enforcement:** Enforced in `session.py` write path

### SEC-004: Responsible use gate
- **Policy:** CLI requires `--authorization {owned|authorized|research}` to run.
- **Rationale:** Legal protection and ethical guardrail. Forces operator to acknowledge authorization.
- **Enforcement:** Typer callback in `commands.py`

---

## License Compliance Log

> Record any license checks performed and findings.

| Date | Action | Finding | Resolution |
|------|--------|---------|------------|
| 2026-03-25 | Initial reference repo audit | All 9 reference tools are MIT or Apache 2.0 | Clean — no GPL/AGPL concerns |
| — | — | — | — |

---

## Issues & Resolutions

> Record any problems encountered and how they were solved.

| Date | Issue | Resolution | Files Affected |
|------|-------|------------|----------------|
| — | — | — | — |
