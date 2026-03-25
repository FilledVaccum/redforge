# Changelog

All notable changes to RedForge will be documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [0.1.0] - 2026-03-25

### Added
- Initial release of RedForge
- 10 attack probes covering full OWASP LLM Top 10
- 9 model adapters: OpenAI, Anthropic, Gemini, Ollama, Bedrock, Azure, Mistral, HuggingFace (local), Generic REST
- CLI with `scan`, `list-probes`, `report`, `serve` commands
- REST API (FastAPI) with Bearer auth, rate limiting, OpenAPI docs
- Python SDK: `from redforge import Scanner, ScanConfig`
- 4 report formats: JSON, SARIF 2.1, HTML, Markdown
- Docker + docker-compose zero-config deployment
- GitHub Actions CI (lint, typecheck, test, pip-audit, license check)
- OWASP LLM Top 10 + MITRE ATLAS probe mapping
- Apache 2.0 license, DCO contribution model
