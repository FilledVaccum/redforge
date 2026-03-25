# Contributing to RedForge

Thank you for your interest in contributing to RedForge!

## Developer Certificate of Origin (DCO)

By contributing to RedForge, you agree that your contributions are submitted under the **Apache License 2.0** and that you have the right to submit them.

All commits must be signed off using the DCO:

```
git commit -s -m "feat: add new probe for LLM01"
```

This adds a `Signed-off-by: Your Name <your@email.com>` line to your commit, certifying that you wrote the code and have the right to contribute it under Apache 2.0.

## License Requirements for Contributions

- All code must be original or derived from Apache-2.0/MIT/BSD-licensed sources
- **No GPL, LGPL, or AGPL code** may be introduced
- All new attack probe payloads must be **original CC0** — no copying from copyrighted datasets
- New dependencies must be Apache-2.0, MIT, BSD-2, BSD-3, or ISC licensed

## Adding a New Attack Probe

1. Create `redforge/probes/your_probe.py`
2. Inherit from `BaseProbe` in `redforge/probes/base.py`
3. Set `id`, `owasp_id`, `mitre_atlas`, `severity`, `description`, `tags`
4. Implement `payloads() -> list[str]` with original CC0 prompts
5. Implement `score(response: str, payload: str) -> ProbeResult`
6. Add tests in `tests/unit/test_probes.py`
7. The probe auto-registers via the registry in `probes/__init__.py`

## Adding a New Model Adapter

1. Create `redforge/adapters/your_adapter.py`
2. Inherit from `BaseAdapter` in `redforge/adapters/base.py`
3. Implement `async send(messages, **kwargs) -> AdapterResponse`
4. Implement `classmethod from_config(config) -> YourAdapter`
5. Add optional dependency to `pyproject.toml` under `[project.optional-dependencies]`
6. Add tests in `tests/unit/test_adapters.py`

## Code Quality

All contributions must pass:
- `ruff check .` — zero lint errors
- `mypy redforge/` — zero type errors
- `pytest tests/` — all tests pass
- `pip-audit` — zero high/critical CVEs
- `detect-secrets scan` — zero secrets detected

## Security Review Checklist

Before submitting a PR, verify:
- [ ] No `eval()` or `exec()` on model-returned content
- [ ] No hardcoded API keys or secrets
- [ ] New probes use only original CC0 payloads
- [ ] New dependencies are license-compliant
- [ ] Commit is signed off with DCO (`git commit -s`)
