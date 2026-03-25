# Security Policy

## Responsible Use

RedForge is a security testing tool designed exclusively for:

- Testing AI/LLM systems **you own**
- Testing systems you have **explicit written authorization** to test
- **Academic and security research** in controlled environments
- **CTF competitions** and authorized penetration testing engagements

**RedForge must NOT be used against systems you do not own or have written permission to test.**
Unauthorized use may violate computer fraud laws including the CFAA (US), Computer Misuse Act (UK), and equivalent laws in other jurisdictions.

## Reporting a Vulnerability

If you discover a security vulnerability in RedForge itself, please report it responsibly:

1. **Do NOT open a public GitHub issue** for security vulnerabilities
2. Email a description of the vulnerability to the maintainers
3. Include: description, reproduction steps, potential impact, and any suggested mitigations
4. Allow 90 days for a fix before public disclosure

## Security Design Principles

RedForge is built with the following security invariants:

- **No eval() on model output**: All LLM responses are treated as untrusted strings
- **Key isolation**: API keys are never logged, stored in plaintext, or included in reports
- **File permissions**: Scan results are stored with `0600` permissions (owner-read-only)
- **Authorization gate**: The CLI requires explicit `--authorization` acknowledgment
- **API authentication**: All REST endpoints require Bearer token authentication
- **Dependency audit**: All dependencies are scanned for CVEs on every CI run

## Prohibited Uses

The following uses are explicitly prohibited:

- Scanning AI systems without owner authorization
- Using RedForge to develop offensive tools for unauthorized use
- Distributing modified versions that remove the authorization gate
- Using scan results to attack or compromise AI systems
