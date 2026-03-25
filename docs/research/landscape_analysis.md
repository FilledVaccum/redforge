# RedForge — LLM Security Tool Landscape Analysis
> Compiled during Phase 0 research. Inspiration only — no code copied.

---

## NVIDIA/garak (Apache 2.0)

**Architecture:** 5-layer plugin system: probes → detectors → generators → harnesses → buffs (prompt transforms). Attempt objects carry prompt+response+scores through the pipeline. JSONL report + HTML digest output.

**What to adopt conceptually:**
- Probe/detector separation (generate payload vs score response)
- Plugin discovery via directory scan (one class per file)
- Attempt dataclass as the unit of work
- SARIF output support (analyze/sarif.py)
- Buff concept: orthogonal prompt transformations (encoding, paraphrase)

**What to avoid:**
- 9GB+ mandatory dependency footprint (torch, transformers, etc.) — RedForge must be lightweight
- No Docker support out of the box
- Config system is complex 4-layer cascade — RedForge uses simpler YAML + env vars
- JSONL-only intermediate format — RedForge outputs JSON, SARIF, HTML, Markdown

**License:** Apache 2.0 — inspiration only

---

## promptfoo/promptfoo (MIT — joined OpenAI 2026-03-16)

**Architecture:** YAML-config-driven eval + red teaming. Node.js CLI (`promptfoo eval`, `promptfoo redteam`). Provider abstraction layer. LLM-as-judge scoring. CI/CD first-class citizen.

**What to adopt conceptually:**
- `--format` flag for multiple output types
- Provider config as YAML (RedForge: adapter config in scan config)
- LLM-as-judge scoring pattern for subjective probe results
- CI/CD exit codes blocking pipelines on critical findings

**What to avoid:**
- Node.js/TypeScript — RedForge is pure Python
- YAML-only config (RedForge supports YAML + CLI args + Python SDK)

**License:** MIT — inspiration only

---

## msoedov/agentic_security (MIT)

**Architecture:** FastAPI server on port 8718. Probe dataset aggregator — pulls from 80+ external jailbreak datasets. RL-based adaptive attacks. Multimodal (text/image/audio). Stress testing mode.

**What to adopt conceptually:**
- FastAPI server pattern (RedForge's API follows similar pattern)
- Dataset aggregator concept — probe registry that loads from multiple sources
- `--port` / `--host` CLI flags for server mode

**What to avoid:**
- External dataset dependency — RedForge bundles its own original CC0 prompts
- No authentication on the API — RedForge enforces Bearer token auth

**License:** MIT — inspiration only

---

## cyberark/FuzzyAI (Apache 2.0)

**Architecture:** Poetry project. `fuzzyai fuzz` CLI. Attack modules as plugins. WebUI (experimental). Ollama integration for local attacker models.

**What to adopt conceptually:**
- Attack module plugin pattern (one class per attack strategy)
- WebUI concept (future roadmap for RedForge)
- Using a local LLM as the red-team attacker (meta-attack pattern)

**What to avoid:**
- Poetry as build system — RedForge uses pyproject.toml with pip/uv
- No API — RedForge provides full REST API

**License:** Apache 2.0 — inspiration only

---

## microsoft/PyRIT (MIT)

**Architecture:** Multi-turn orchestrators, memory/conversation tracking, scoring engine, prompt injection datasets. Azure-first but provider-agnostic. Python SDK primary interface.

**What to adopt conceptually:**
- Multi-turn attack orchestration (conversation-aware attacks)
- Memory/history tracking across turns
- Scoring as a first-class object (not just pass/fail)

**What to avoid:**
- Azure-first design bias — RedForge is cloud-agnostic
- Heavyweight class hierarchy

**License:** MIT — inspiration only

---

## Key Design Decisions for RedForge

1. **Lightweight core** — no torch/transformers in base install. Optional extras for local HF models.
2. **Probe-integrated scoring** — unlike garak's probe+detector split, RedForge probes include their own scorer for simplicity. Extensible to external judges.
3. **Docker-first** — zero-config `docker-compose up` from day one.
4. **Three interfaces parity** — CLI, REST API, Python SDK all expose identical functionality.
5. **Original payloads** — no scraping from copyrighted datasets. All prompts are original CC0.
6. **OWASP LLM Top 10 mapped** — every probe has an OWASP ID and MITRE ATLAS reference.
