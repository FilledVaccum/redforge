# Changelog

All notable changes to RedForge are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versions follow [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

---

## [0.3.0] - 2026-03-26

### Added — Modular Extensibility Refactor

**`core/constants.py`** — single source of truth
- `AUTHORIZATION_CHOICES` tuple used by both CLI and SDK (was duplicated in two files)
- `SEVERITY_META` dict: severity → `{rich_color, hex_color, risk_level}`
- `SEVERITY_HEX`, `SEVERITY_RICH` derived dicts — all severity-aware code now imports from here
- Adding a new severity level requires one entry in this file; everything else adapts automatically

**`core/scorer.py`** — severity-agnostic scoring
- `ScanScore.findings_by_severity: dict[str, int]` replaces 4 hardcoded fields (`critical_findings`, `high_findings`, `medium_findings`, `low_findings`)
- Backward-compat `@property` shims preserve all existing code without changes
- `score_results()` now counts failures for any severity string dynamically — unknown severities scored at weight 0.5, never silently dropped
- Risk level determined by `_RISK_THRESHOLDS` table, not per-severity if/elif chains
- New `info_findings` property added

**`probes/base.py`** — self-describing probes
- `BaseProbe.remediation: str` — probe-specific remediation text; reporters use this instead of external lookup dicts
- `BaseProbe.guardrail_meta: dict` — detection hints for guardrail pipeline; `failures_reporter.py` uses this directly
- `BaseProbe.compliance: dict[str, list[str]]` — compliance framework → control IDs mapping
- `BaseProbe.refusal_signals: list[str]` — class attribute; subclasses extend without overriding `_refusal_detected()`
- `_make_result()` copies all metadata into `ProbeResult` automatically
- `ProbeResult` gets `remediation`, `guardrail_meta`, `compliance` fields

**`reporters/__init__.py`** — auto-discovery
- Reporters now auto-discovered via `pkgutil.iter_modules` + `inspect.getmembers` — same pattern as probes
- Adding a reporter requires only creating a file; no `__init__.py` or `commands.py` edits needed
- `fmt_aliases: list[str]` on `BaseReporter` for extra format names (e.g. `"md"` for `"markdown"`)
- `available_formats()` returns primary format names without aliases
- `MarkdownReporter` gains `fmt_aliases = ["md"]`

**`reporters/base.py`**
- `save()` now applies `os.chmod(0o600)` on all reporter output (was only in specific reporters)
- `fmt_aliases` class attribute for alias registration

**`reporters/html_reporter.py`**
- `SEVERITY_COLORS` is now `SEVERITY_HEX` from `constants.py` — same object, never stale
- Finding remediation uses probe-level `r.remediation` first, then static `_OWASP_REMEDIATION` dict, then generic message
- Executive summary severity callouts generated dynamically from `findings_by_severity` — any new severity level appears automatically

**`reporters/failures_reporter.py`**
- `_build_failure_entry()` uses probe-level `guardrail_meta` first, then static `_OWASP_GUARDRAIL_META`, then generic fallback
- New OWASP categories (LLM11+) never crash or produce wrong output

**`cli/commands.py`**
- Provider help text derived from `AdapterFactory._registry` at runtime — never stale
- Format help text derived from `available_formats()` at runtime — never stale
- New `list-providers` command: live table of all registered providers and report formats
- Uses `AUTHORIZATION_CHOICES` from `core/constants.py`
- Severity colors derived from `SEVERITY_RICH` — adapts to new severity levels automatically

**`core/session.py`**
- Session JSON now includes `findings_by_severity` dict alongside existing summary fields

### Fixed
- Authorization choices were duplicated in `cli/commands.py` and `redforge/__init__.py` — now single source of truth in `core/constants.py`
- Reporters silently produced incorrect or empty guidance for OWASP categories beyond LLM10 — graceful fallback chain implemented
- `ScanScore` rejected future severity levels by silently scoring them as 0 — now always counted

---

## [0.2.0] - 2026-03-26

### Added — Universal HuggingFace Adapter

**HuggingFace adapter** (`adapters/huggingface_adapter.py`) — works with any model on the Hub
- Four modes: `inference_api` (serverless), `endpoint` (dedicated), `tgi` (self-hosted TGI ≥ 2.0), `local` (transformers pipeline)
- **No catalog entry needed** — any HuggingFace model ID works, including ones that don't exist yet
- **Hub API capability detection**: queries `huggingface.co/api/models/{id}?fields=pipeline_tag` on first call (5 s timeout, non-blocking, never fails a scan)
- Maps 15+ `pipeline_tag` values to optimal starting strategy
- **Strategy waterfall** (inference_api): `chat_completion` → `text_generation` → `text2text_generation` → `conversational`
- **Strategy cache**: module-level dict with 1 h TTL — subsequent calls on the same model skip detection entirely
- `clear_strategy_cache()` exported for test isolation
- Error classification: HTTP 422/400/"not supported" = strategy skip; HTTP 429/503/timeout = retry same strategy
- **Mode auto-detection** from `base_url`: `endpoints.huggingface.cloud` → `endpoint`; `:8080` → `tgi`; any other URL → `endpoint`
- Local pipeline: 3-attempt fallback (chat template → plain text prompt → text2text)
- Removed hardcoded `_CHAT_CAPABLE_PREFIXES` list — replaced by dynamic detection
- `HuggingFaceAdapter` registered in `AdapterFactory._BUILTIN_REGISTRY`

### Added — Adapter Middle Layer

**`adapters/model_catalog.py`**
- `ModelSpec` dataclass: provider, model_id, display_name, context_window, costs, rate_limits, tags, aliases
- `BedrockModelFamily` enum: ANTHROPIC, META_LLAMA, MISTRAL, AMAZON_TITAN, COHERE, AI21
- `get_bedrock_family()` auto-detects Bedrock model family from model ID prefix
- 72-model catalog across 10 providers (46 original + 26 HuggingFace)
- HuggingFace catalog: Llama 3.1/3.2, Mistral, Gemma 2, Phi-3.5, Qwen 2.5, DeepSeek R1/V3, StarCoder2, CodeLlama, Zephyr, Command R+, Falcon
- Helper functions: `get_model()`, `list_models()`, `resolve_alias()`, `search_models()`
- O(1) alias index built at import time

**`adapters/adapter_config.py`**
- `AdapterConfig` typed dataclass: provider, model, base_url, api_key_env, region, deployment_name, timeout, max_retries, temperature, max_tokens, extra_headers, extra_params, profile
- `AdapterConfig.from_spec()` parses `"provider/model[@url_or_region][#profile]"` — HuggingFace `org/model` format handled correctly
- `AdapterConfig.from_dict()` validates and type-coerces YAML/CLI dicts
- `AdapterConfig.to_provider_config()` converts to per-adapter flat dict

**`adapters/factory.py`**
- `AdapterFactory.from_spec()`, `from_profile()`, `from_config()`, `from_dict()`, `register()`
- `AdapterFactory.health_check()` → `HealthCheckResult(ok, provider, model, latency_ms, error)`
- `AdapterFactory.detect_available()` → checks Ollama `/api/tags`, env vars, AWS credentials
- Lazy loading via `importlib` — provider SDKs only imported when that adapter is actually used
- `_custom_registry` for runtime third-party adapter registration

**`adapters/profiles.py`**
- `ConnectionProfile` dataclass: name, config, description, tags
- `ProfileManager` searches: `./redforge.profiles.yaml` → `~/.redforge/profiles.yaml` → `$REDFORGE_PROFILES`
- `_builtin_profiles()` auto-generates one profile per `MODEL_CATALOG` entry — 132 built-in profiles, zero user configuration needed
- User YAML profiles layer on top of built-ins; user definitions always win
- `ProfileManager.save()` persists profiles to YAML

**`redforge.profiles.yaml.example`**
- Comprehensive reference YAML covering all 72 catalog models
- OpenAI (7 models), Anthropic (5), Gemini (4), Mistral (4), Bedrock (13), Azure (2), Ollama (11), HuggingFace (12 examples), REST
- HuggingFace section covers all 4 modes with full usage examples
- Preset profiles: `quick-local`, `deep-scan`, `ci`

**`adapters/bedrock_adapter.py`** — rewritten
- Routes per `BedrockModelFamily`: Anthropic, Meta Llama, Mistral, Amazon Titan, Cohere, AI21
- Each family has a dedicated `_*_body()` builder and `_extract_response_content()` parser
- Llama: `<|begin_of_text|><|start_header_id|>` format; Mistral: `<s>[INST]` format; Titan: `inputText`; Cohere: `message + chat_history`; AI21: OpenAI-style messages

### Added — Scan Output Reports

**`reporters/audit_reporter.py`**
- JSONL format: one JSON object per line — `session_start`, one `probe_result` per result, `session_end`
- Every entry: probe metadata, attack payload + sha256, model output + sha256, score, verdict, evidence
- Written with `os.chmod(0o600)` — owner-read-only
- `AuditReporter` registered as `"audit"` format

**`reporters/failures_reporter.py`**
- Failures-only structured JSON for guardrail improvement
- Each failure: probe info, full payload, full response, guardrail detection hints, YARA rule template, similarity reference, recommended action
- `_OWASP_GUARDRAIL_META` maps LLM01–LLM10 to detector type, scan target, action
- `_extract_patterns()` pulls keyword signals from payload and response
- `_build_yara_template()` generates ready-to-use YARA rule dict with `usage` code snippet
- `_build_guardrail_summary()` produces `input_scanner_gaps`, `output_scanner_gaps`, `priority_actions`
- `FailuresReporter` registered as `"failures"` format

**`core/orchestrator.py`**
- `_save_auto_reports()` called after every scan — writes `{stem}_audit.jsonl` and `{stem}_failures.json` unconditionally
- No CLI flag required — audit and failures files are always produced
- Skips failures file if no failures exist; skips both if `store_results=False`

---

## [0.1.0] - 2026-03-25

### Added — Initial Release

- 47 attack probes covering full OWASP LLM Top 10 with MITRE ATLAS mappings
- 9 model adapters: OpenAI, Anthropic, Gemini, Ollama, Bedrock, Azure, Mistral, HuggingFace (initial), Generic REST
- CLI: `scan`, `list-probes`, `report`, `serve` commands (Typer)
- REST API (FastAPI): Bearer auth, rate limiting (10 req/min), OpenAPI docs at `/docs`
- Python SDK: `from redforge import Scanner, ScanConfig`
- Report formats: JSON, SARIF 2.1, HTML (sanitized, with compliance table), Markdown
- CVSS-style risk scoring: weighted sum of failed probe scores → 0.0–10.0
- Scan session management with `os.chmod(0o600)` on all result files
- Compliance mapping: NIST AI RMF, EU AI Act, ISO/IEC 42001, GDPR, OWASP LLM Top 10
- Docker: non-root user (uid 1001), read-only filesystem, compose file
- GitHub Actions CI: lint (ruff), typecheck (mypy), tests (pytest), pip-audit, license check
- GitHub issue templates (bug, feature), PR template with security checklist
- Apache 2.0 license, DCO contribution model
- Website: classified intelligence document aesthetic, deployed to Vercel

---

[Unreleased]: https://github.com/FilledVaccum/redforge/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/FilledVaccum/redforge/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/FilledVaccum/redforge/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/FilledVaccum/redforge/releases/tag/v0.1.0
