# RedForge

**Production-grade LLM Red Teaming & Vulnerability Scanning Platform**

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![OWASP LLM Top 10](https://img.shields.io/badge/OWASP-LLM%20Top%2010-red.svg)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)

> **For authorized use only.** Scan only systems you own or have explicit written permission to test.

RedForge is a security tool for red teaming large language models. It tests LLMs against the [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/) and [MITRE ATLAS](https://atlas.mitre.org/) attack taxonomy, producing findings in JSON, SARIF, HTML, and Markdown formats suitable for CI/CD pipelines and security audits.

---

## Architecture

```
                         INTERFACES
     CLI (Typer)         REST API (FastAPI)      Python SDK
     redforge scan       POST /v1/scan           Scanner(...)
          |                    |                      |
          +--------------------+----------------------+
                               |
                        Orchestrator
                       (async scan loop)
                               |
          +--------------------+--------------------+
          |                    |                    |
       Probes              Adapters             Reporters
   (10 OWASP probes)   (9 LLM providers)   JSON/SARIF/HTML/MD
          |                    |
     ProbeResult         AdapterResponse
          +--------------------+
                    |
                 Scorer
            (CVSS-style 0-10)
                    |
               ScanReport
          (0600 local storage)
```

---

## Features

- **10 attack probes** covering the full OWASP LLM Top 10 (LLM01–LLM10)
- **9 provider adapters**: OpenAI, Anthropic, Google Gemini, Ollama, AWS Bedrock, Azure OpenAI, Mistral, and any generic REST endpoint
- **4 output formats**: JSON, SARIF 2.1.0, HTML (XSS-safe), Markdown
- **REST API** with Bearer auth, rate limiting (10 req/min), and path traversal protection
- **CI/CD integration**: exits non-zero on critical/high findings; SARIF output for GitHub Code Scanning
- **Security-by-design**: no `eval()`/`exec()` on model output; API keys masked in logs; results stored at `0600`; authorization gate required

---

## Quick Start

### Installation

```bash
pip install redforge

# With a specific provider (optional extras):
pip install "redforge[openai]"
pip install "redforge[anthropic]"
pip install "redforge[openai,anthropic]"
```

### CLI

```bash
# List all available probes
redforge list-probes

# Scan a local Ollama model (no API key needed)
redforge scan --provider ollama --model llama3 --authorization owned

# Scan OpenAI GPT-4o and save HTML report
redforge scan \
  --provider openai \
  --model gpt-4o \
  --authorization owned \
  --format html \
  --output report.html

# Dry run — show which probes would fire without calling the API
redforge scan --provider openai --authorization owned --dry-run

# Output SARIF for GitHub Code Scanning
redforge scan --provider openai --authorization owned --format sarif --output results.sarif

# Start the REST API server
redforge serve --port 8000
```

The `--authorization` flag is required and must be one of:

| Value | Meaning |
|-------|---------|
| `owned` | You own this model/system |
| `authorized` | You have written permission to test it |
| `research` | Controlled research environment |

### Python SDK

```python
import asyncio
from redforge import Scanner

scanner = Scanner(provider="ollama", model="llama3")
report = asyncio.run(scanner.scan(authorization="owned"))

print(f"Risk: {report.score.risk_level} ({report.score.risk_score:.1f}/10)")
print(f"Probes: {report.score.passed}/{report.score.total_probes} passed")

for finding in report.results:
    if not finding.passed:
        print(f"  FAIL [{finding.owasp_id}] {finding.probe_id}: {finding.evidence}")
```

### REST API

```bash
export REDFORGE_API_KEY="your-secret-key"
redforge serve --port 8000

# List probes
curl -H "Authorization: Bearer $REDFORGE_API_KEY" http://localhost:8000/v1/probes

# Run a scan
curl -X POST http://localhost:8000/v1/scan \
  -H "Authorization: Bearer $REDFORGE_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"provider": "ollama", "authorization": "owned", "dry_run": true}'

# API docs
open http://localhost:8000/docs
```

---

## Probes (OWASP LLM Top 10)

| ID | OWASP | MITRE ATLAS | Severity | Description |
|----|-------|-------------|----------|-------------|
| `RF-001-prompt-injection` | LLM01 | AML.T0051 | Critical | Prompt injection and jailbreak |
| `RF-002-sensitive-disclosure` | LLM02 | AML.T0024 | High | PII and sensitive data extraction |
| `RF-003-rag-poisoning` | LLM03 | AML.T0020 | High | RAG context manipulation |
| `RF-004-data-poisoning` | LLM04 | AML.T0020 | High | Training data poisoning signals |
| `RF-005-improper-output` | LLM05 | AML.T0043 | High | Unsafe code/XSS/SQLi generation |
| `RF-006-excessive-agency` | LLM06 | AML.T0047 | Critical | Unauthorized action execution |
| `RF-007-system-prompt-leak` | LLM07 | AML.T0056 | Medium | System prompt extraction |
| `RF-008-embedding-weakness` | LLM08 | AML.T0054 | Medium | Embedding inversion attacks |
| `RF-009-hallucination` | LLM09 | AML.T0048 | Medium | Fabrication and overconfidence |
| `RF-010-many-shot` | LLM10 | AML.T0051 | High | Many-shot jailbreaking |

---

## Docker

```bash
# Build
docker build -f docker/Dockerfile -t redforge .

# Run scan via Docker
docker run --rm \
  -e OPENAI_API_KEY="$OPENAI_API_KEY" \
  -v "$(pwd)/results:/app/scan_results" \
  redforge \
  redforge scan --provider openai --authorization owned --format sarif --output /app/scan_results/results.sarif

# Start API server
docker compose -f docker/docker-compose.yml up
```

The container runs as non-root user `redforge` (uid 1001) with a read-only filesystem.

---

## CI/CD Integration

RedForge exits with code `1` when critical or high findings are detected, making it suitable as a CI gate.

### GitHub Actions

```yaml
- name: LLM Security Scan
  run: |
    pip install "redforge[openai]"
    redforge scan \
      --provider openai \
      --model gpt-4o \
      --authorization authorized \
      --format sarif \
      --output redforge.sarif
  env:
    OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: redforge.sarif
```

---

## Providers

| Provider | Extra | Key Env Var |
|----------|-------|-------------|
| OpenAI | `pip install "redforge[openai]"` | `OPENAI_API_KEY` |
| Anthropic | `pip install "redforge[anthropic]"` | `ANTHROPIC_API_KEY` |
| Google Gemini | `pip install "redforge[gemini]"` | `GOOGLE_API_KEY` |
| AWS Bedrock | `pip install "redforge[bedrock]"` | AWS credentials via env |
| Azure OpenAI | base install | `AZURE_OPENAI_API_KEY`, `AZURE_OPENAI_ENDPOINT` |
| Mistral | `pip install "redforge[mistral]"` | `MISTRAL_API_KEY` |
| Ollama | base install | none (local) |
| Generic REST | base install | `REDFORGE_REST_API_KEY` (optional) |

---

## Security

RedForge is designed to handle untrusted model output safely:

- Model responses are **never** passed to `eval()`, `exec()`, or any shell execution
- API keys are **masked as `***`** in all log output
- Scan results are stored with **`0600` permissions** (owner-read-only)
- The REST API requires a **Bearer token** (`REDFORGE_API_KEY` env var)
- Session IDs are validated with `isalnum()` before use in file paths (path traversal prevention)
- CORS is disabled by default (`allow_origins=[]`)

To report a security vulnerability, see [SECURITY.md](SECURITY.md).

---

## Development

```bash
git clone https://github.com/redforge/redforge
cd redforge
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Lint and type check
ruff check .
mypy redforge/

# Security audit
pip-audit
pip-licenses --allow-only="MIT;Apache Software License;BSD License;ISC License (ISCL);Python Software Foundation License;Mozilla Public License 2.0 (MPL 2.0)"
```

---

## License

Apache 2.0. See [LICENSE](LICENSE).

RedForge is a clean-room implementation. It draws architectural inspiration from the LLM security research ecosystem (garak, promptfoo, PyRIT) but shares no code with any of those projects. All probe payloads are original and released under CC0.

See [NOTICE](NOTICE) and [RESEARCH_LOG.md](RESEARCH_LOG.md) for full attribution.
