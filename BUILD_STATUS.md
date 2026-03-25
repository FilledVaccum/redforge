# RedForge — Build Status Dashboard
> Single-glance view of the entire project state.
> Updated at the end of each phase.

---

## Current Phase: NOT STARTED

```
Phase 0 — Research        [ PENDING  ]  ░░░░░░░░░░░░░░░░░░░░  0%
Phase 1 — Architecture    [ PENDING  ]  ░░░░░░░░░░░░░░░░░░░░  0%
Phase 2 — Build           [ PENDING  ]  ░░░░░░░░░░░░░░░░░░░░  0%
Phase 3 — Security        [ PENDING  ]  ░░░░░░░░░░░░░░░░░░░░  0%
Phase 4 — Validation      [ PENDING  ]  ░░░░░░░░░░░░░░░░░░░░  0%
Phase 5 — Polish          [ PENDING  ]  ░░░░░░░░░░░░░░░░░░░░  0%
─────────────────────────────────────────────────────────────
OVERALL                   [ PENDING  ]  ░░░░░░░░░░░░░░░░░░░░  0/104 tasks
```

---

## File Checklist

### Root Files
| File | Status | Notes |
|------|--------|-------|
| `LICENSE` | PENDING | Apache 2.0 |
| `NOTICE` | PENDING | Third-party attributions |
| `SECURITY.md` | PENDING | Responsible use + disclosure |
| `CONTRIBUTING.md` | PENDING | DCO + Apache 2.0 terms |
| `README.md` | PENDING | Quickstart + architecture |
| `CHANGELOG.md` | PENDING | v0.1.0 |
| `pyproject.toml` | PENDING | Pinned deps, metadata |
| `.gitignore` | PENDING | Secrets, results, dist |
| `.pre-commit-config.yaml` | PENDING | detect-secrets, ruff, mypy |
| `TASKS.md` | CREATED | This tracker |
| `BUILD_STATUS.md` | CREATED | This file |
| `RESEARCH_LOG.md` | CREATED | Research decisions |

### Core Package
| File | Status | Notes |
|------|--------|-------|
| `redforge/__init__.py` | PENDING | Public SDK surface |
| `redforge/utils/secrets.py` | PENDING | Key masking |
| `redforge/utils/rate_limiter.py` | PENDING | Backoff logic |
| `redforge/core/orchestrator.py` | PENDING | Scan loop |
| `redforge/core/scorer.py` | PENDING | CVSS-style scoring |
| `redforge/core/session.py` | PENDING | 0600 result files |

### Adapters (9 files)
| Adapter | Status | Providers Covered |
|---------|--------|------------------|
| `base.py` | PENDING | Abstract interface |
| `openai_adapter.py` | PENDING | OpenAI, gpt-4o, gpt-4-turbo |
| `anthropic_adapter.py` | PENDING | Claude 3.x, Claude 4.x |
| `gemini_adapter.py` | PENDING | Gemini 1.5, 2.0 |
| `ollama_adapter.py` | PENDING | Ollama local models |
| `bedrock_adapter.py` | PENDING | AWS Bedrock |
| `azure_adapter.py` | PENDING | Azure OpenAI |
| `generic_rest_adapter.py` | PENDING | Any REST endpoint |
| `mistral_adapter.py` | PENDING | Mistral AI |

### Probes (11 files — OWASP LLM Top 10)
| Probe | OWASP ID | Status | Severity |
|-------|----------|--------|----------|
| `base.py` | — | PENDING | — |
| `prompt_injection.py` | LLM01 | PENDING | Critical |
| `sensitive_disclosure.py` | LLM02 | PENDING | High |
| `rag_poisoning.py` | LLM03 | PENDING | High |
| `data_poisoning.py` | LLM04 | PENDING | High |
| `improper_output.py` | LLM05 | PENDING | Medium |
| `excessive_agency.py` | LLM06 | PENDING | Critical |
| `system_prompt_leak.py` | LLM07 | PENDING | High |
| `embedding_weakness.py` | LLM08 | PENDING | Medium |
| `hallucination.py` | LLM09 | PENDING | Medium |
| `many_shot.py` | LLM10 | PENDING | High |

### Reporters (5 files)
| Reporter | Status | Output Format |
|----------|--------|--------------|
| `base.py` | PENDING | Abstract |
| `json_reporter.py` | PENDING | JSON |
| `sarif_reporter.py` | PENDING | SARIF 2.1 |
| `html_reporter.py` | PENDING | HTML (sanitized) |
| `markdown_reporter.py` | PENDING | Markdown |

### API (7 files)
| File | Status | Notes |
|------|--------|-------|
| `app.py` | PENDING | FastAPI factory, CORS, rate limiter |
| `auth.py` | PENDING | Bearer token middleware |
| `models.py` | PENDING | Pydantic schemas |
| `routes/scan.py` | PENDING | POST /v1/scan |
| `routes/probes.py` | PENDING | GET /v1/probes |
| `routes/reports.py` | PENDING | GET /v1/reports/{id} |

### CLI (1 file)
| File | Status | Commands |
|------|--------|---------|
| `commands.py` | PENDING | scan, list-probes, report, serve |

### Infrastructure
| File | Status | Notes |
|------|--------|-------|
| `docker/Dockerfile` | PENDING | Non-root user |
| `docker/docker-compose.yml` | PENDING | Full stack |
| `.github/workflows/ci.yml` | PENDING | lint+test+audit+license |
| `.github/workflows/release.yml` | PENDING | cosign + SBOM |

### Tests (6 files)
| File | Status | Coverage Target |
|------|--------|----------------|
| `tests/unit/test_probes.py` | PENDING | All 10 probes |
| `tests/unit/test_scorer.py` | PENDING | Scoring logic |
| `tests/unit/test_adapters.py` | PENDING | Adapter interface |
| `tests/unit/test_reporters.py` | PENDING | All 4 formats |
| `tests/integration/test_cli.py` | PENDING | All CLI commands |
| `tests/integration/test_api.py` | PENDING | All API endpoints |

---

## Security Checklist

| Control | Status | Verified By |
|---------|--------|-------------|
| Zero `eval()` on model output | PENDING | `grep -r "eval(" redforge/` |
| Zero hardcoded secrets | PENDING | `detect-secrets scan` |
| API Bearer auth enforced | PENDING | `tests/integration/test_api.py` |
| Rate limiting on API | PENDING | Code review |
| CORS restricted by default | PENDING | Code review |
| Result files `0600` perms | PENDING | Code review |
| `--authorization` gate on CLI | PENDING | `tests/integration/test_cli.py` |
| Keys masked in logs | PENDING | Code review |
| Non-root Docker user | PENDING | `docker inspect` |
| No GPL/AGPL deps | PENDING | `pip-licenses` |
| All deps CVE-clean | PENDING | `pip-audit` |
| GitHub Actions SHAs pinned | PENDING | Code review |

---

## CI Gate Results

| Check | Last Run | Result | Notes |
|-------|----------|--------|-------|
| `ruff check .` | — | — | — |
| `mypy redforge/` | — | — | — |
| `pytest tests/` | — | — | — |
| `pip-audit` | — | — | — |
| `pip-licenses` | — | — | — |
| `detect-secrets scan` | — | — | — |
| `docker build` | — | — | — |

---

## Completion Criteria

RedForge is **DONE** when all of the following are true:

1. All 104 tasks in `TASKS.md` are `[x]`
2. All CI gate results above are PASS
3. All security checklist items are VERIFIED
4. `redforge scan --target ollama --authorization owned --dry-run` completes
5. `docker-compose up` starts cleanly with zero manual config
6. README quickstart works in under 60 seconds from `pip install redforge`
