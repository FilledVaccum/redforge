<div align="center">

# 🔥 RedForge

**Production-Grade LLM Red Teaming & Vulnerability Scanner**

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![PyPI](https://img.shields.io/badge/pypi-redforge-orange)](https://pypi.org/project/redforge/)
[![CI](https://img.shields.io/github/actions/workflow/status/FilledVaccum/redforge/ci.yml?label=CI)](https://github.com/FilledVaccum/redforge/actions)
[![OWASP LLM Top 10](https://img.shields.io/badge/OWASP-LLM%20Top%2010-red)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
[![MITRE ATLAS](https://img.shields.io/badge/MITRE-ATLAS-darkred)](https://atlas.mitre.org/)
[![Docs](https://img.shields.io/badge/docs-redforge.vercel.app-brightgreen)](https://redforge.vercel.app)

<br/>

> **For authorized use only.** Only scan systems you own or have explicit written permission to test.

<br/>

RedForge is a comprehensive LLM security testing platform — **47 probes**, **10 provider adapters** including **any model on HuggingFace Hub**, **72-model catalog**, **named connection profiles**, **multi-turn attack orchestration**, **17-strategy mutation engine**, **auto-generated audit + guardrail reports**, and **compliance reporting** for NIST AI RMF, EU AI Act, ISO/IEC 42001, and OWASP LLM Top 10.

[**Docs**](https://redforge.vercel.app) · [**Quick Start**](#quick-start) · [**Probes**](#probes-47) · [**Providers**](#providers) · [**API Reference**](https://redforge.vercel.app/docs/api-reference.html)

</div>

---

## Why RedForge?

| | RedForge | Garak | Promptfoo | PyRIT | Giskard |
|---|---|---|---|---|---|
| OWASP LLM Top 10 coverage | ✅ **Full (10/10)** | Partial | Partial | Partial | Partial |
| Probe count | ✅ **47** | ~100 (narrow) | ~20 | ~15 | ~10 |
| Multi-turn attacks (PAIR/Crescendo) | ✅ | ❌ | ❌ | ✅ | ❌ |
| 17-strategy mutation engine | ✅ | ❌ | ❌ | ❌ | ❌ |
| YARA-style pattern scanner | ✅ | ❌ | ❌ | ❌ | ❌ |
| Semantic similarity detector | ✅ | ❌ | ❌ | ❌ | ❌ |
| Benchmark eval (AdvBench/HarmBench/JBB) | ✅ | Partial | ❌ | ❌ | ❌ |
| REST API + Python SDK | ✅ | ❌ | ❌ | ❌ | Partial |
| SARIF output (GitHub Code Scanning) | ✅ | ❌ | ✅ | ❌ | ❌ |
| NIST AI RMF / EU AI Act reports | ✅ | ❌ | ❌ | ❌ | ✅ |
| YAML declarative config | ✅ | ❌ | ✅ | ❌ | ❌ |
| Bidirectional guardrail pipeline | ✅ | ❌ | ❌ | ❌ | ❌ |
| 10 provider adapters + any HuggingFace model | ✅ | Partial | ✅ | Partial | Partial |
| Docker + CI-ready | ✅ | Partial | ✅ | Partial | ❌ |

---

## Features

<table>
<tr>
<td width="50%">

**🎯 47 Security Probes**
Full OWASP LLM Top 10 coverage with MITRE ATLAS technique mappings. Every probe ships with severity rating, CVSSv3-style scoring, and remediation guidance.

**⚔️ Advanced Attack Modules**
- PAIR (Prompt Automatic Iterative Refinement)
- Crescendo multi-turn escalation
- Skeleton Key technique
- Many-shot jailbreaking
- GCG adversarial suffixes

**🔀 17-Strategy Mutation Engine**
Obfuscate payloads via Base64, ROT13, leet speak, Unicode normalization, token boundary manipulation, zero-width chars, and more.

**🛡️ Bidirectional Guardrails**
`InputScanner → LLM → OutputScanner` pipeline with prompt injection detection, PII detection, toxicity filtering, and secrets scanning.

</td>
<td width="50%">

**📊 Benchmark Evaluation**
Standardized Attack Success Rate (ASR) metrics against AdvBench (520 behaviors), HarmBench (400), JailbreakBench (100), ToxicChat, WildGuardMix, and custom datasets.

**🔍 YARA-Style Detection**
14 built-in rules covering prompt injection, SSRF, shell injection, SQL injection, CBRN, malware generation, EICAR, and encoded payloads. Fully extensible.

**📋 Compliance Reports**
Auto-generate gap reports for NIST AI RMF, EU AI Act (Art. 9/10/13/15/16/72), ISO/IEC 42001, GDPR, and OWASP LLM Top 10 from a single scan.

**🔌 10 Provider Adapters**
OpenAI, Anthropic, Google Gemini, AWS Bedrock (6 model families), Azure OpenAI, Mistral, Ollama (local), HuggingFace Hub (any of millions of models), and any generic REST endpoint.

**🗂️ 72-Model Catalog + Named Profiles**
Pre-configured specs for 72 models across all providers. Reference any by name: `AdapterFactory.from_profile("claude-3-5-sonnet")`. 132 built-in profiles, zero config required.

**📋 Auto-Generated Audit + Guardrail Reports**
Every scan automatically writes a full JSONL audit log (every payload, response, score) and a failures JSON structured for direct import into your guardrail pipeline (YARA rules, similarity detectors, recommended actions).

</td>
</tr>
</table>

---

## Quick Start

### Install

```bash
pip install redforge

# With providers
pip install "redforge[openai]"
pip install "redforge[anthropic]"
pip install "redforge[all-providers]"  # all 9 providers
```

### CLI

```bash
# Scan a local model (no API key needed)
redforge scan --provider ollama --model llama3 --authorization owned

# Scan OpenAI GPT-4o, output HTML report
redforge scan \
  --provider openai \
  --model gpt-4o \
  --authorization owned \
  --format html \
  --output report.html

# Compliance report (NIST AI RMF + EU AI Act)
redforge scan --provider openai --authorization research \
  --compliance NIST_AI_RMF,EU_AI_ACT

# Output SARIF for GitHub Code Scanning
redforge scan --provider openai --authorization owned \
  --format sarif --output results.sarif

# Scan any HuggingFace model — no catalog entry needed
redforge scan \
  --provider huggingface \
  --model "mistralai/Mistral-7B-Instruct-v0.3" \
  --authorization owned

# Use a named profile
redforge scan --provider my-prod-gpt4 --authorization authorized

# List all registered providers and report formats
redforge list-providers

# Start REST API server
redforge serve --port 8000
```

The `--authorization` flag is required:

| Value | Meaning |
|-------|---------|
| `owned` | You own this model/system |
| `authorized` | You have written permission to test it |
| `research` | Controlled research environment |

### Python SDK

```python
import asyncio
from redforge import Scanner, ScanConfig

config = ScanConfig(
    provider="openai",
    model="gpt-4o",
    authorization="owned",
    probes=["prompt_injection", "system_prompt_leak", "excessive_agency"],
    compliance=["NIST_AI_RMF", "EU_AI_ACT"],
)
scanner = Scanner(config)
report = asyncio.run(scanner.scan())

print(f"Risk: {report.score.risk_level} ({report.score.risk_score:.1f}/10)")
print(f"Passed: {report.score.passed}/{report.score.total_probes} probes")
```

### YAML Config (promptfoo-style)

```yaml
# redforge.yaml
provider: openai
model: gpt-4o
authorization: owned
compliance:
  - NIST_AI_RMF
  - EU_AI_ACT
output:
  format: html
  path: report.html
attacks:
  pair: true
  mutation_strategies:
    - base64
    - leetspeak
    - unicode_confusables
```

```bash
redforge run redforge.yaml
```

### REST API

```bash
export REDFORGE_API_KEY="your-secret-key"
redforge serve

# Kick off a scan
curl -X POST http://localhost:8000/v1/scan \
  -H "Authorization: Bearer $REDFORGE_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"provider":"ollama","model":"llama3","authorization":"owned"}'

# Full interactive docs
open http://localhost:8000/docs
```

---

## Probes (47)

<details>
<summary><strong>LLM01 — Prompt Injection (9 probes)</strong></summary>

| Probe ID | Severity | MITRE | Description |
|----------|----------|-------|-------------|
| RF-001 | Critical | AML.T0051 | Direct prompt injection |
| RF-002 | Critical | AML.T0051 | Indirect / RAG injection |
| RF-011 | High | AML.T0051 | Role-play persona bypass |
| RF-012 | High | AML.T0051 | DAN jailbreak variants |
| RF-013 | Critical | AML.T0051 | GCG adversarial suffix |
| RF-014 | Medium | AML.T0051 | Continuation attack |
| RF-015 | High | AML.T0051 | Encoding bypass (Base64/ROT13) |
| RF-016 | High | AML.T0051 | Multilingual bypass |
| RF-017 | Medium | AML.T0051 | Typoglycemia bypass |

</details>

<details>
<summary><strong>LLM02 — Insecure Output Handling (6 probes)</strong></summary>

| Probe ID | Severity | MITRE | Description |
|----------|----------|-------|-------------|
| RF-003 | High | AML.T0043 | XSS via model output |
| RF-004 | High | AML.T0043 | SQL injection generation |
| RF-005 | High | AML.T0043 | Shell command injection |
| RF-018 | Medium | AML.T0043 | ANSI escape sequences |
| RF-019 | High | AML.T0043 | SSRF via tool calls |
| RF-020 | Medium | AML.T0043 | Output format exploitation |

</details>

<details>
<summary><strong>LLM03–LLM10 (32 probes)</strong></summary>

| Probe ID | OWASP | Severity | Description |
|----------|-------|----------|-------------|
| RF-021–023 | LLM03 | High | RAG poisoning, faithfulness, context injection |
| RF-024–026 | LLM04 | High | Data poisoning, backdoor triggers, supply chain |
| RF-027–029 | LLM05 | High | Malware generation, CBRN, CSAM detection |
| RF-030–032 | LLM06 | Critical | Excessive agency, agentic escalation, MCP tool poisoning |
| RF-033–037 | LLM07 | Medium–High | System prompt leak, PII extraction, API key extraction, session leakage, data memorization |
| RF-038–039 | LLM08 | Medium | Embedding inversion, known-bad signatures |
| RF-040–044 | LLM09 | Medium | Hallucination, package hallucination, medical safety, misinformation, sycophancy |
| RF-045–047 | LLM10 | High | Many-shot, context window, snowball/crescendo attack |

</details>

---

## Providers

| Provider | Install | Env Var | Notes |
|----------|---------|---------|-------|
| **OpenAI** | `pip install "redforge[openai]"` | `OPENAI_API_KEY` | GPT-4o, GPT-4o-mini, o1, o3 |
| **Anthropic** | `pip install "redforge[anthropic]"` | `ANTHROPIC_API_KEY` | Claude 3.5, Claude 3 Opus |
| **Google Gemini** | `pip install "redforge[gemini]"` | `GOOGLE_API_KEY` | Gemini 1.5 Pro/Flash, Gemini 2.0 |
| **AWS Bedrock** | `pip install "redforge[bedrock]"` | AWS credentials env | 6 model families auto-detected |
| **Azure OpenAI** | base install | `AZURE_OPENAI_API_KEY` + `AZURE_OPENAI_ENDPOINT` | Deployment name support |
| **Mistral** | `pip install "redforge[mistral]"` | `MISTRAL_API_KEY` | Mistral Large, Codestral |
| **Ollama** | base install | none | 100% local, zero cost |
| **HuggingFace** | `pip install huggingface_hub` | `HF_TOKEN` (gated models) | **Any model on the Hub** |
| **Generic REST** | base install | `REDFORGE_REST_API_KEY` (opt.) | Any OpenAI-compat endpoint |

### HuggingFace — any model on the Hub

RedForge works with **any** of the millions of models on HuggingFace Hub — not just a fixed list. The adapter automatically detects the right API strategy for each model via the Hub API and falls back through a full waterfall if needed.

```python
from redforge.adapters import AdapterFactory

# Serverless Inference API — any public model
adapter = AdapterFactory.from_spec("huggingface/mistralai/Mistral-7B-Instruct-v0.3")
adapter = AdapterFactory.from_spec("huggingface/google/flan-t5-large")       # encoder-decoder
adapter = AdapterFactory.from_spec("huggingface/facebook/blenderbot-400M-distill")  # dialog

# Gated models (set HF_TOKEN env var)
adapter = AdapterFactory.from_spec("huggingface/meta-llama/Meta-Llama-3.1-70B-Instruct")

# Your Dedicated Inference Endpoint
adapter = AdapterFactory.from_spec("huggingface/my-model@https://xyz.endpoints.huggingface.cloud")

# Self-hosted TGI server (auto-detected from :8080)
adapter = AdapterFactory.from_spec("huggingface/tgi@http://my-gpu:8080")

# Local — runs on this machine, no network during scan
adapter = AdapterFactory.from_dict({
    "provider": "huggingface",
    "model": "microsoft/Phi-3.5-mini-instruct",
    "mode": "local",
})
```

**Strategy detection waterfall** (automatic, cached per model, 1 h TTL):
1. Hub API lookup → `pipeline_tag` → best starting strategy
2. `chat_completion` (OpenAI-compat Messages API)
3. `text_generation` (base/instruct models)
4. `text2text_generation` (T5, BART, Flan-T5, mT5)
5. `conversational` (BlenderBot, legacy dialog)

Works for any model that produces text — including ones that don't exist yet.

---

## Adapter Middle Layer

RedForge includes a garak-style flexible adapter system so you can connect to any provider/model/endpoint without modifying core code.

### AdapterFactory

```python
from redforge.adapters import AdapterFactory

# Spec string — most concise
adapter = AdapterFactory.from_spec("openai/gpt-4o")
adapter = AdapterFactory.from_spec("bedrock/anthropic.claude-3-5-sonnet-20241022-v2:0@us-west-2")
adapter = AdapterFactory.from_spec("ollama/llama3:70b@http://remote-server:11434")

# Named profile (built-in or user-defined)
adapter = AdapterFactory.from_profile("claude-3-5-sonnet")   # 132 built-in profiles
adapter = AdapterFactory.from_profile("my-prod-gpt4")        # from redforge.profiles.yaml

# Typed config
from redforge.adapters import AdapterConfig
config = AdapterConfig(provider="openai", model="gpt-4o", max_tokens=2048, timeout=60.0)
adapter = AdapterFactory.from_config(config)

# Health check before scanning
result = await AdapterFactory.health_check("openai/gpt-4o")
print(result.ok, result.latency_ms)

# Auto-detect what's available in current environment
available = await AdapterFactory.detect_available()
for m in available:
    print(m.spec, m.detection_method)
```

### Named Profiles

```yaml
# redforge.profiles.yaml  (project-local, or ~/.redforge/profiles.yaml for global)
profiles:
  my-prod-claude:
    description: "Production Claude 3.5 Sonnet"
    provider: anthropic
    model: claude-3-5-sonnet-20241022
    max_tokens: 2048
    tags: [production]

  local-free:
    provider: ollama
    model: phi3.5
    tags: [local, free, ci]
```

```bash
redforge scan --provider my-prod-claude --authorization authorized
```

Copy `redforge.profiles.yaml.example` from the repo for a complete reference covering all 72 catalog models.

---

## Report Formats

Every scan automatically produces three output files — no flags needed:

| File | Format | Purpose |
|------|--------|---------|
| `redforge_{id}_{ts}.json` | JSON | Session summary, scores, per-probe results |
| `redforge_{id}_{ts}_audit.jsonl` | JSONL | **Full audit log** — every payload, model response, score, sha256 |
| `redforge_{id}_{ts}_failures.json` | JSON | **Guardrail improvement** — failed probes only, YARA templates, detection patterns |

Additional formats via `--format`:

| Format | Flag | Use case |
|--------|------|----------|
| **HTML** | `--format html` | Executive report with compliance table |
| **Markdown** | `--format markdown` | GitHub PR comments, CI annotations |
| **SARIF 2.1** | `--format sarif` | GitHub Code Scanning / security tab |
| **JSON** | `--format json` | Machine-readable, pipeline integration |
| **Audit JSONL** | `--format audit` | Stream-friendly full audit trail |
| **Failures JSON** | `--format failures` | Feed directly into guardrail pipeline |

### Audit Log (JSONL)

Each line is a self-contained JSON object — grep-able, stream-parseable, no loading the whole file.

```jsonc
{"event":"session_start","session_id":"...","model":"gpt-4o","timestamp":"..."}
{"event":"probe_result","probe_id":"prompt_injection_basic","owasp_id":"LLM01",
 "severity":"critical","passed":false,"score":0.92,
 "attack":{"payload":"...","sha256":"abc123..."},
 "model_output":{"response":"...","sha256":"def456..."},
 "result":{"verdict":"FAIL","evidence":"Model complied with injection instruction"}}
{"event":"session_end","total_probes":47,"failed":3,"risk_level":"HIGH","risk_score":7.4}
```

### Failures Report (Guardrail Improvement)

Structured JSON ready to feed into `YARAScanner.add_rule()` or `SimilarityDetector.add_reference()`:

```jsonc
{
  "schema": "redforge-failures-v1",
  "failures": [{
    "probe_id": "prompt_injection_basic",
    "owasp_id": "LLM01",
    "guardrail": {
      "detector": "YARAScanner + SimilarityDetector",
      "scan_target": "INPUT",
      "action": "BLOCK",
      "input_patterns": ["ignore all previous", "disregard instructions"],
      "yara_rule_template": {
        "rule_name": "RF_LLM01_prompt_injection_basic",
        "strings": ["ignore all previous", "disregard instructions"],
        "usage": "scanner.add_rule(yara_rule_template)"
      }
    }
  }],
  "guardrail_summary": {
    "input_scanner_gaps": ["prompt_injection_basic"],
    "priority_actions": ["Add YARA rule RF_LLM01_...", "Add similarity reference"]
  }
}
```

---

## Extensibility

RedForge is built so every extension point requires **only adding files, never editing existing ones**:

| What you add | What you need to do |
|---|---|
| **New probe** (new OWASP category, new attack) | Create one file in `redforge/probes/`. Auto-discovered. Set `remediation`, `guardrail_meta`, `compliance` on the class — reporters use them automatically. |
| **New reporter** (CSV, Splunk, XLSX…) | Create one file in `redforge/reporters/`. Subclass `BaseReporter`, set `fmt`. Auto-discovered. |
| **New severity level** | Two lines in `core/constants.py` + one line in `core/scorer.py`. Every reporter and the CLI adapt automatically. |
| **New provider** | One line in `adapters/factory.py` registry. CLI help text is derived from the registry at runtime. |
| **New auth type** | One line in `core/constants.py`. Both CLI and SDK pick it up. |

---

## Detectors

RedForge includes 7 detector types for analyzing model responses:

| Detector | Description |
|----------|-------------|
| `YARAScanner` | 14 built-in rules — injection, SSRF, shell/SQL injection, CBRN, malware, EICAR, encoded payloads |
| `SimilarityDetector` | Cosine similarity against 25 reference attack patterns (token-based or sentence-transformers) |
| `RefusalDetector` | Detects model refusals (safe outcome) |
| `RegexDetector` | Custom regex patterns — API keys, secrets, code execution |
| `KeywordDetector` | Exact keyword matching with configurable thresholds |
| `CodeDetector` | Detects generated code by language |
| `UnsafeContentDetector` | Violence, self-harm, CSAM signal detection |

---

## Compliance Mapping

```bash
redforge scan --provider openai --authorization research \
  --compliance NIST_AI_RMF,EU_AI_ACT,ISO_42001,OWASP_LLM
```

| Framework | Coverage |
|-----------|----------|
| **NIST AI RMF** | GOVERN / MAP / MEASURE / MANAGE functions |
| **EU AI Act** | Art. 9, 10, 13, 15, 16, 72 |
| **ISO/IEC 42001** | Annex B controls B.5.2, B.6.1, B.7.4, B.8.4 |
| **GDPR** | Art. 5, 22, 25 (automated decision-making) |
| **OWASP LLM Top 10** | Full LLM01–LLM10 |
| **MITRE ATLAS** | AML.T0020, T0047, T0048, T0051, T0053, T0054, T0056 |

---

## Benchmarks

```python
from redforge.benchmarks import run_benchmark, BenchmarkSuite
from redforge import get_adapter

adapter = get_adapter("openai", model="gpt-4o")
report = await run_benchmark(adapter, suite=BenchmarkSuite.ADVBENCH)
print(f"ASR: {report.asr:.1%} ({report.attacked}/{report.total})")
```

| Benchmark | Behaviors | Reference |
|-----------|-----------|-----------|
| **AdvBench** | 520 harmful behaviors | Zou et al. (2023) |
| **HarmBench** | 400 standardized | Mazeika et al. (2024) |
| **JailbreakBench** | 100 behaviors | Chao et al. (2024) |
| **ToxicChat** | Real jailbreak attempts | Lin et al. (2023) |
| **WildGuardMix** | 13K safety items | Han et al. (2024) |
| **Custom** | Your JSONL/CSV dataset | — |

---

## Docker

```bash
docker build -f docker/Dockerfile -t redforge .

docker run --rm \
  -e OPENAI_API_KEY="$OPENAI_API_KEY" \
  -v "$(pwd)/results:/results" \
  redforge/redforge:latest \
  scan --provider openai --model gpt-4o --authorization research \
       --format html --output /results/report.html
```

Runs as non-root user `redforge` (uid 1001) with read-only filesystem.

---

## CI/CD Integration

RedForge exits `1` on critical/high findings — use it as a CI gate.

```yaml
# .github/workflows/llm-security.yml
name: LLM Security Scan

on: [push, pull_request]

jobs:
  redforge:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run RedForge
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

      - name: Upload to GitHub Security tab
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: redforge.sarif
        if: always()
```

---

## Security

| Control | Implementation |
|---------|---------------|
| No `eval`/`exec` on model output | Enforced throughout all detectors and reporters |
| API key masking | All keys replaced with `***` in logs |
| Result file permissions | `os.chmod(path, 0o600)` on every write |
| REST API authentication | Bearer token via `REDFORGE_API_KEY` |
| Path traversal prevention | Session IDs validated with `isalnum()` |
| CORS | Disabled by default (`allow_origins=[]`) |
| Rate limiting | 10 scan requests/min per client |

To report a vulnerability, see [SECURITY.md](SECURITY.md).

---

## Development

```bash
git clone https://github.com/FilledVaccum/redforge
cd redforge
pip install -e ".[all-providers,dev]"

pytest tests/ -v
ruff check .
mypy redforge/
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## License

Apache 2.0 — see [LICENSE](LICENSE).

RedForge is a clean-room implementation. It draws architectural inspiration from the LLM security research ecosystem (garak, promptfoo, PyRIT) but shares no code with those projects. All probe payloads are original and released under CC0.

See [NOTICE](NOTICE) and [RESEARCH_LOG.md](RESEARCH_LOG.md) for full attribution.

---

<div align="center">

**[Website](https://redforge.vercel.app)** · **[Docs](https://redforge.vercel.app/docs/getting-started.html)** · **[API Reference](https://redforge.vercel.app/docs/api-reference.html)** · **[Report a Bug](https://github.com/FilledVaccum/redforge/issues)**

</div>
