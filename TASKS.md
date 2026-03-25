# RedForge — Master Task Tracker
> Status legend: `[ ]` = pending | `[~]` = in_progress | `[x]` = completed | `[!]` = blocked
> Last updated: 2026-03-25
> This file is updated by Claude Code TaskUpdate in real time — never batch updates.

---

## PHASE 0 — Research & Orientation

### 0.1 — Local Repo Analysis
- [ ] Scan `/home/sagemaker-user/Garak/` structure with `Glob`
- [ ] Read `Garak/` README, pyproject.toml, probe architecture
- [ ] Scan any other local LLM security repos under `/home/sagemaker-user/`
- [ ] Extract: adapter patterns, probe interface design, CLI ergonomics

### 0.2 — GitHub Research
- [ ] Fetch `promptfoo/promptfoo` README via `gh api`
- [ ] Fetch `microsoft/PyRIT` README via `gh api`
- [ ] Fetch `protectai/llm-guard` README via `gh api`
- [ ] Fetch `EasyJailbreak/EasyJailbreak` README via `gh api`
- [ ] Fetch `Giskard-AI/giskard-oss` README via `gh api`
- [ ] Fetch `cyberark/FuzzyAI` README via `gh api`
- [ ] Fetch `msoedov/agentic_security` README via `gh api`
- [ ] Search `topic:llm-fuzzing` for any new tools not yet in the list

### 0.3 — Research Artifacts
- [ ] Write `docs/research/landscape_analysis.md` — per-tool analysis
- [ ] Write `docs/research/attack_taxonomy.md` — unified probe registry
- [ ] Write `docs/research/license_audit.md` — confirm all reference tool licenses
- [ ] Write `docs/research/dependency_candidates.md` — approved deps and their licenses

### 0.4 — Phase 0 Sign-off
- [ ] All research findings documented
- [ ] No GPL/AGPL deps identified in candidate dependency list
- [ ] No copyrighted prompt datasets identified for use

---

## PHASE 1 — Architecture Design

- [ ] Enter Plan Mode (`EnterPlanMode`)
- [ ] Write `docs/ARCHITECTURE.md` — component diagram, data flow, security boundaries
- [ ] Define `probes/base.py` interface contract (abstract class spec)
- [ ] Define `adapters/base.py` interface contract (abstract class spec)
- [ ] Define `reporters/base.py` interface contract (abstract class spec)
- [ ] Exit Plan Mode (`ExitPlanMode`)
- [ ] Architecture reviewed — no security anti-patterns present

---

## PHASE 2 — Project Scaffold

### 2.1 — Root Files
- [ ] `LICENSE` (Apache 2.0 full text)
- [ ] `NOTICE` (third-party attribution template)
- [ ] `SECURITY.md` (responsible disclosure + authorized use policy)
- [ ] `CONTRIBUTING.md` (DCO + Apache 2.0 contribution terms)
- [ ] `README.md` (quickstart, ASCII architecture, examples, disclaimer)
- [ ] `CHANGELOG.md` (initial entry)
- [ ] `pyproject.toml` (all deps pinned, Apache 2.0 metadata, ruff+mypy config)
- [ ] `.gitignore` (secrets, .env, results, __pycache__, dist)
- [ ] `.pre-commit-config.yaml` (detect-secrets, ruff, mypy)

### 2.2 — Package Structure
- [ ] `redforge/__init__.py` (public SDK surface: Scanner, ScanConfig)
- [ ] `redforge/utils/__init__.py`
- [ ] `redforge/utils/secrets.py` (safe credential loading, key masking)
- [ ] `redforge/utils/rate_limiter.py` (exponential backoff per provider)

### 2.3 — Model Adapters
- [ ] `redforge/adapters/__init__.py`
- [ ] `redforge/adapters/base.py` (AbstractAdapter interface)
- [ ] `redforge/adapters/openai_adapter.py`
- [ ] `redforge/adapters/anthropic_adapter.py`
- [ ] `redforge/adapters/gemini_adapter.py`
- [ ] `redforge/adapters/ollama_adapter.py`
- [ ] `redforge/adapters/bedrock_adapter.py`
- [ ] `redforge/adapters/azure_adapter.py`
- [ ] `redforge/adapters/generic_rest_adapter.py`

### 2.4 — Attack Probes (one file per OWASP LLM category)
- [ ] `redforge/probes/__init__.py` (probe registry loader)
- [ ] `redforge/probes/base.py` (BaseProbe abstract class)
- [ ] `redforge/probes/prompt_injection.py` (LLM01)
- [ ] `redforge/probes/sensitive_disclosure.py` (LLM02)
- [ ] `redforge/probes/rag_poisoning.py` (LLM03)
- [ ] `redforge/probes/data_poisoning.py` (LLM04)
- [ ] `redforge/probes/improper_output.py` (LLM05)
- [ ] `redforge/probes/excessive_agency.py` (LLM06)
- [ ] `redforge/probes/system_prompt_leak.py` (LLM07)
- [ ] `redforge/probes/embedding_weakness.py` (LLM08)
- [ ] `redforge/probes/hallucination.py` (LLM09)
- [ ] `redforge/probes/many_shot.py` (LLM10)

### 2.5 — Core Engine
- [ ] `redforge/core/__init__.py`
- [ ] `redforge/core/orchestrator.py` (scan loop, probe dispatch, result aggregation)
- [ ] `redforge/core/scorer.py` (CVSS-style scoring per probe result)
- [ ] `redforge/core/session.py` (scan session state, result storage with 0600 perms)

### 2.6 — Reporters
- [ ] `redforge/reporters/__init__.py`
- [ ] `redforge/reporters/base.py` (BaseReporter abstract class)
- [ ] `redforge/reporters/json_reporter.py`
- [ ] `redforge/reporters/sarif_reporter.py`
- [ ] `redforge/reporters/html_reporter.py` (sanitized — no raw model output in HTML)
- [ ] `redforge/reporters/markdown_reporter.py`

### 2.7 — CLI
- [ ] `redforge/cli/__init__.py`
- [ ] `redforge/cli/commands.py` (`scan`, `list-probes`, `report`, `serve` with `--authorization` gate)

### 2.8 — REST API
- [ ] `redforge/api/__init__.py`
- [ ] `redforge/api/app.py` (FastAPI app factory, CORS config, rate limiter setup)
- [ ] `redforge/api/auth.py` (Bearer token middleware)
- [ ] `redforge/api/models.py` (Pydantic request/response schemas)
- [ ] `redforge/api/routes/__init__.py`
- [ ] `redforge/api/routes/scan.py` (`POST /v1/scan`)
- [ ] `redforge/api/routes/probes.py` (`GET /v1/probes`)
- [ ] `redforge/api/routes/reports.py` (`GET /v1/reports/{id}`)

### 2.9 — Docker
- [ ] `docker/Dockerfile` (non-root user, minimal base, no secrets baked in)
- [ ] `docker/docker-compose.yml` (API + env var injection)

### 2.10 — CI/CD
- [ ] `.github/workflows/ci.yml` (ruff, mypy, pytest, pip-audit, pip-licenses)
- [ ] `.github/workflows/release.yml` (cosign signing, CycloneDX SBOM)

### 2.11 — Tests
- [ ] `tests/unit/test_probes.py` (each probe generates valid payloads)
- [ ] `tests/unit/test_scorer.py` (scoring logic)
- [ ] `tests/unit/test_adapters.py` (adapter interface contract)
- [ ] `tests/unit/test_reporters.py` (output format validation)
- [ ] `tests/integration/test_cli.py` (CLI commands with mock adapter)
- [ ] `tests/integration/test_api.py` (API endpoints with auth)

---

## PHASE 3 — Security Hardening Verification

- [ ] `Grep` for `eval(` in `redforge/` — must return zero hits on model content
- [ ] `Grep` for `exec(` in `redforge/` — must return zero hits
- [ ] `Grep` for hardcoded key patterns (`sk-`, `Bearer `, `api_key =`) — zero hits
- [ ] Verify `.gitignore` covers `.env`, `*.results.json`, `scan_results/`
- [ ] Verify `session.py` uses `os.chmod(path, 0o600)` for result files
- [ ] Verify `--authorization` gate present in CLI `scan` command
- [ ] Verify `api/auth.py` blocks unauthenticated requests with 401
- [ ] Verify `api/app.py` has rate limiting and request size limits
- [ ] Verify CORS is `allow_origins=[]` by default
- [ ] Verify `secrets.py` masks keys in all log output
- [ ] Verify Docker runs as non-root user
- [ ] Run `pip-licenses --fail-on="GPL;LGPL;AGPL"` — zero failures

---

## PHASE 4 — Validation Gates

- [ ] `ruff check .` — zero errors
- [ ] `mypy redforge/` — zero type errors
- [ ] `pytest tests/ -v` — all tests pass
- [ ] `pip-audit` — zero high/critical CVEs
- [ ] `pip-licenses` — zero GPL/AGPL/LGPL
- [ ] `detect-secrets scan` — zero secrets detected
- [ ] `docker build -f docker/Dockerfile .` — succeeds
- [ ] `pip install -e . && redforge --help` — works
- [ ] `redforge list-probes` — shows all 10 probes with OWASP IDs
- [ ] `redforge serve` — FastAPI starts, `/docs` accessible
- [ ] `redforge scan --target ollama --authorization owned --dry-run` — completes without error

---

## PHASE 5 — Final Polish

- [ ] README quickstart tested end-to-end (under 60 seconds from `pip install`)
- [ ] `TASKS.md` shows 100% completion
- [ ] All `[~]` in-progress tasks resolved
- [ ] All `[!]` blocked tasks resolved or documented with reason
- [ ] `CHANGELOG.md` updated with v0.1.0 release notes
- [ ] Final `git status` clean — no untracked secrets or result files

---

## Blocked / Issues Log

> Record any blockers here with date and resolution status.

| Date | Task | Blocker | Resolution |
|------|------|---------|------------|
| — | — | — | — |

---

## Progress Summary

| Phase | Total Tasks | Completed | In Progress | Blocked |
|-------|-------------|-----------|-------------|---------|
| Phase 0 — Research | 16 | 0 | 0 | 0 |
| Phase 1 — Architecture | 7 | 0 | 0 | 0 |
| Phase 2 — Scaffold | 52 | 0 | 0 | 0 |
| Phase 3 — Security | 12 | 0 | 0 | 0 |
| Phase 4 — Validation | 11 | 0 | 0 | 0 |
| Phase 5 — Polish | 6 | 0 | 0 | 0 |
| **TOTAL** | **104** | **0** | **0** | **0** |
