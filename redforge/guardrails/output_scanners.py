"""Output scanners for RedForge guardrails.

These scanners evaluate model OUTPUT before it is returned to the user.
"""

from __future__ import annotations

import re

from redforge.guardrails.base import BaseScanner, BaseScanResult


class CredentialLeakScanner(BaseScanner):
    """Detect credential leakage in model output.

    Scans for API keys, tokens, passwords, SSNs, and other credentials
    in model responses that should never be disclosed.
    """

    name = "credential_leak_scanner"
    direction = "output"
    block_threshold = 0.85

    _PATTERNS: list[tuple[str, re.Pattern[str], float]] = [
        ("openai_key", re.compile(r"sk-[a-zA-Z0-9]{20,}"), 1.0),
        ("openai_proj_key", re.compile(r"sk-proj-[a-zA-Z0-9\-_]{30,}"), 1.0),
        ("github_pat", re.compile(r"ghp_[a-zA-Z0-9]{36}"), 1.0),
        ("aws_key", re.compile(r"AKIA[0-9A-Z]{16}"), 1.0),
        ("aws_secret", re.compile(r"[a-zA-Z0-9/+]{40}"), 0.6),
        ("google_api", re.compile(r"AIza[0-9A-Za-z\-_]{35}"), 1.0),
        ("slack_token", re.compile(r"xoxb-[0-9]+-[a-zA-Z0-9]+"), 1.0),
        ("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), 0.9),
        ("credit_card", re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b"), 0.95),
        ("bearer_token", re.compile(r"Bearer\s+[a-zA-Z0-9\-_.]{30,}"), 0.8),
        ("private_key_header", re.compile(r"-----BEGIN (RSA |EC )?PRIVATE KEY-----"), 1.0),
        ("password_field", re.compile(r"password\s*[=:]\s*[^\s]{8,}", re.I), 0.85),
    ]

    def scan(self, text: str, context: dict[str, str] | None = None) -> BaseScanResult:
        found: list[tuple[str, float]] = []

        for name, pattern, confidence in self._PATTERNS:
            if pattern.search(text):
                found.append((name, confidence))

        if not found:
            return self._make_result(0.0, "No credentials detected in output")

        max_conf = max(c for _, c in found)
        names = [n for n, _ in found]

        return self._make_result(
            max_conf,
            f"Credential patterns found in output: {names}",
            names,
        )


class MaliciousCodeScanner(BaseScanner):
    """Detect malicious code patterns in model output.

    Scans for reverse shells, persistence mechanisms, credential harvesters,
    and other malicious code constructs.
    """

    name = "malicious_code_scanner"
    direction = "output"

    _PATTERNS: list[tuple[str, re.Pattern[str], float]] = [
        # Reverse shells
        ("reverse_shell_bash", re.compile(r"bash\s+-i\s+>&\s*/dev/tcp/", re.I), 1.0),
        ("reverse_shell_nc", re.compile(r"nc\s+-e\s+/bin/(sh|bash)", re.I), 1.0),
        ("python_reverse_shell", re.compile(r"socket\.connect\([^)]+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"), 0.9),

        # Persistence
        ("crontab_persistence", re.compile(r"crontab\s+-[el].*@reboot", re.I | re.DOTALL), 0.85),
        ("registry_run_key", re.compile(r"HKEY.*\\Run\b", re.I), 0.9),
        ("systemd_persistence", re.compile(r"\[Service\].*ExecStart.*\n.*\[Install\]", re.I | re.DOTALL), 0.7),

        # Exfiltration
        ("curl_exfil", re.compile(r"curl.*\|\s*base64.*pastebin|webhook|ngrok|requestbin", re.I), 0.9),
        ("data_exfil_requests", re.compile(r"requests\.post\(['\"]https?://[^'\"]+['\"],\s*data=", re.I), 0.7),

        # Obfuscation
        ("base64_exec", re.compile(r"(exec|eval)\s*\(\s*(base64_decode|b64decode)", re.I), 0.95),
        ("hex_shellcode", re.compile(r"\\x[0-9a-f]{2}(\\x[0-9a-f]{2}){15,}", re.I), 0.85),

        # Credential harvesting
        ("keylogger", re.compile(r"(pynput|keyboard\.Listener|win32api\.GetAsyncKeyState)", re.I), 0.9),
        ("mimikatz", re.compile(r"sekurlsa::logonpasswords|lsadump::sam", re.I), 1.0),
        ("passwd_read", re.compile(r"open\('/etc/shadow'|open\('/etc/passwd'", re.I), 0.8),
    ]

    def scan(self, text: str, context: dict[str, str] | None = None) -> BaseScanResult:
        # Only trigger if the response actually contains code-like content
        code_indicators = ["```", "import ", "def ", "function(", "#!", "#!/"]
        has_code = any(ind in text for ind in code_indicators)

        if not has_code:
            return self._make_result(0.0, "No code content detected")

        found: list[tuple[str, float]] = []
        for name, pattern, confidence in self._PATTERNS:
            if pattern.search(text):
                found.append((name, confidence))

        if not found:
            return self._make_result(0.05, "Code present but no malicious patterns detected")

        max_conf = max(c for _, c in found)
        names = [n for n, _ in found]

        return self._make_result(
            max_conf,
            f"Malicious code pattern detected: {names}",
            names,
        )


class ToxicityOutputScanner(BaseScanner):
    """Detect toxic or harmful content in model output.

    Scans for hate speech, violent content, and other toxic patterns
    that should not be returned to users.
    """

    name = "toxicity_output_scanner"
    direction = "output"

    _CATEGORIES: list[tuple[str, list[str], float]] = [
        (
            "hate_speech",
            ["subhuman", "vermin", "exterminate", "ethnic cleansing", "racial inferiority"],
            0.95,
        ),
        (
            "violence",
            ["how to kill", "step-by-step murder", "torture instructions", "maim"],
            0.9,
        ),
        (
            "self_harm",
            ["best method to commit suicide", "how to cut yourself", "overdose instructions"],
            0.95,
        ),
        (
            "csam_adjacent",
            ["sexual content involving minor", "child exploitation", "underage explicit"],
            1.0,
        ),
        (
            "threats",
            ["i will harm you", "i know where you live", "you will regret this"],
            0.85,
        ),
    ]

    def scan(self, text: str, context: dict[str, str] | None = None) -> BaseScanResult:
        r = text.lower()
        found: list[tuple[str, float]] = []

        for category, keywords, severity in self._CATEGORIES:
            if any(kw.lower() in r for kw in keywords):
                found.append((category, severity))

        if not found:
            return self._make_result(0.0, "No toxic content detected in output")

        max_sev = max(s for _, s in found)
        cats = [c for c, _ in found]

        return self._make_result(
            max_sev,
            f"Toxic content categories detected: {cats}",
            cats,
        )
