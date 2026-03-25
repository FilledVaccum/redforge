## Summary

<!-- Describe what this PR does and why -->

## Type of Change

- [ ] Bug fix
- [ ] New probe
- [ ] New provider adapter
- [ ] New detector / attack module
- [ ] Documentation
- [ ] Refactor / performance
- [ ] CI/CD

## Probes Added / Modified

<!-- If adding a new probe, fill this in -->

| Probe ID | OWASP | MITRE ATLAS | Severity |
|----------|-------|-------------|----------|
| RF-XXX   |       |             |          |

## Testing

- [ ] `pytest tests/ -v` passes
- [ ] `ruff check .` passes
- [ ] `mypy redforge/` passes
- [ ] New probes have unit tests in `tests/unit/test_probes.py`

## Security Checklist

- [ ] No `eval()`/`exec()` on model-returned content
- [ ] API keys are not logged or committed
- [ ] No new dependencies added without updating `pyproject.toml`

## Related Issues

Closes #
