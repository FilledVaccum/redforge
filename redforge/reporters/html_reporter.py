"""HTML reporter — sanitized, with executive summary, remediation, and compliance."""

from __future__ import annotations

import html
from typing import TYPE_CHECKING

from redforge.core.constants import SEVERITY_HEX
from redforge.reporters.base import BaseReporter

if TYPE_CHECKING:
    from redforge.core.orchestrator import ScanReport

# Derived from SEVERITY_HEX — adapts automatically when new severities are added.
SEVERITY_COLORS = SEVERITY_HEX

# Per-OWASP remediation guidance.
# Reporters use ProbeResult.remediation first (set by probe class).
# This dict is the fallback for probes that don't set their own remediation text.
# Entries here cover LLM01–LLM10; new OWASP categories handled by probe-level metadata.
_OWASP_REMEDIATION: dict[str, str] = {
    "LLM01": "Implement prompt hardening: use structured message formats, validate input boundaries, deploy instruction hierarchy enforcement. Test with adversarial prompt suites before production.",
    "LLM02": "Audit training data for PII memorization. Deploy output filtering for credentials and personal data. Consider differential privacy techniques for fine-tuning.",
    "LLM03": "Validate all RAG source documents before injection. Implement source attribution and integrity checks on retrieved context. Monitor for context manipulation patterns.",
    "LLM04": "Audit AI model and dependency supply chain. Pin model versions, generate SBOMs, scan for tampered weights. Verify model provenance before deployment.",
    "LLM05": "Never execute model-generated code without human review. Implement output sanitization, XSS/SQL injection scanning on generated content, and sandboxed execution environments.",
    "LLM06": "Apply principle of least privilege to all AI agents. Require human-in-the-loop for high-impact actions. Implement action audit logging, scope boundaries, and kill switches.",
    "LLM07": "Avoid embedding secrets or sensitive logic in system prompts. Treat system prompts as potentially observable. Use secure credential management instead.",
    "LLM08": "Apply differential privacy to embedding generation. Audit for embedding inversion attack vectors. Monitor similarity queries for data extraction patterns.",
    "LLM09": "Implement factual grounding via RAG. Require citations for factual claims. Deploy uncertainty quantification and hallucination detection in production pipelines.",
    "LLM10": "Monitor input token lengths for many-shot patterns. Implement sliding-window analysis on conversation context. Rate-limit excessively long single-turn inputs.",
}


class HTMLReporter(BaseReporter):
    fmt = "html"

    def render(self, report: ScanReport) -> str:
        s = report.score
        color = SEVERITY_COLORS.get(s.risk_level.lower(), "#6b7280")

        # SECURITY: All user-controlled strings are html.escape()'d before rendering.
        # Raw model response content is NOT rendered — only evidence strings.
        findings_html = self._render_findings(report)
        compliance_html = self._render_compliance(report)
        exec_summary = self._render_exec_summary(report)
        started = html.escape(str(report.session.started_at)[:19]) if report.session.started_at else "—"

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>RedForge Security Report — {html.escape(report.session_id[:8])}</title>
  <style>
    *{{box-sizing:border-box}}
    body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;margin:0;background:#f1f5f9;color:#0f172a}}
    .header{{background:linear-gradient(135deg,#0f172a 0%,#1e293b 100%);color:white;padding:28px 40px}}
    .header h1{{margin:0 0 4px;font-size:22px;letter-spacing:-.5px}}
    .header .sub{{font-size:12px;opacity:.6}}
    .container{{max-width:1100px;margin:0 auto;padding:32px 20px}}
    .card{{background:white;border-radius:12px;padding:24px;margin-bottom:20px;box-shadow:0 1px 4px rgba(0,0,0,.08)}}
    .risk-header{{display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:16px}}
    .risk-badge{{display:inline-block;padding:6px 16px;border-radius:99px;color:white;background:{color};font-weight:800;font-size:15px;letter-spacing:.5px}}
    .score-big{{font-size:48px;font-weight:900;color:{color};line-height:1}}
    .score-denom{{font-size:20px;color:#94a3b8;font-weight:400}}
    .grid4{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-top:20px}}
    @media(max-width:600px){{.grid4{{grid-template-columns:repeat(2,1fr)}}}}
    .stat{{background:#f8fafc;border-radius:8px;padding:14px;text-align:center;border:1px solid #e2e8f0}}
    .stat-n{{font-size:26px;font-weight:800}}
    .stat-l{{font-size:11px;color:#64748b;margin-top:3px;text-transform:uppercase;letter-spacing:.5px}}
    .section-title{{font-size:18px;font-weight:700;margin:0 0 16px;color:#0f172a;display:flex;align-items:center;gap:8px}}
    .finding{{background:white;border-radius:10px;padding:20px;margin-bottom:12px;border-left:5px solid;box-shadow:0 1px 3px rgba(0,0,0,.06)}}
    .finding-header{{display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:8px}}
    .finding h3{{margin:0 0 6px;font-size:14px;font-family:monospace;color:#0f172a}}
    .badge{{display:inline-block;padding:3px 9px;border-radius:5px;font-size:11px;font-weight:700;color:white;margin-right:4px}}
    .score-bar-wrap{{width:100%;background:#f1f5f9;border-radius:99px;height:6px;margin:10px 0}}
    .score-bar{{height:6px;border-radius:99px;transition:width .4s ease}}
    .evidence{{background:#f8fafc;border-radius:6px;padding:10px 14px;font-size:12px;color:#475569;margin-top:10px;border:1px solid #e2e8f0;line-height:1.5}}
    .remediation{{background:#eff6ff;border-radius:6px;padding:10px 14px;font-size:12px;color:#1e40af;margin-top:8px;border:1px solid #bfdbfe}}
    .remediation strong{{display:block;margin-bottom:3px;font-size:11px;text-transform:uppercase;letter-spacing:.5px;color:#1d4ed8}}
    .exec-box{{background:#fefce8;border:1px solid #fde047;border-radius:8px;padding:16px 20px;font-size:13px;color:#713f12;line-height:1.6}}
    .compliance-table{{width:100%;border-collapse:collapse;font-size:12px}}
    .compliance-table th{{background:#f1f5f9;padding:8px 12px;text-align:left;font-weight:700;color:#374151;border-bottom:2px solid #e2e8f0}}
    .compliance-table td{{padding:8px 12px;border-bottom:1px solid #f1f5f9;vertical-align:top}}
    .compliance-table tr:hover td{{background:#fafafa}}
    .pass{{color:#16a34a;font-weight:700}}
    .fail{{color:#dc2626;font-weight:700}}
    .tag{{display:inline-block;background:#e0e7ff;color:#3730a3;border-radius:4px;padding:1px 6px;font-size:10px;margin:1px}}
    footer{{text-align:center;padding:32px;color:#94a3b8;font-size:12px}}
    .no-findings{{background:#d1fae5;border-radius:10px;padding:24px;text-align:center;font-weight:700;color:#065f46;font-size:16px}}
    .warn-box{{background:#fff7ed;border:1px solid #fed7aa;border-radius:8px;padding:12px 16px;font-size:12px;color:#9a3412;margin-bottom:20px}}
  </style>
</head>
<body>
  <div class="header">
    <h1>RedForge LLM Security Report</h1>
    <div class="sub">Session {html.escape(report.session_id)} &nbsp;|&nbsp; {started} &nbsp;|&nbsp; v0.1.0</div>
  </div>
  <div class="container">
    <div class="warn-box">
      For authorized use only. This report contains findings from a security assessment conducted with explicit authorization.
    </div>

    <!-- Risk Overview -->
    <div class="card">
      <div class="risk-header">
        <div>
          <div style="font-size:12px;color:#64748b;text-transform:uppercase;letter-spacing:.5px;margin-bottom:4px">Target</div>
          <div style="font-weight:700;font-size:16px">{html.escape(report.session.target)}</div>
          <div style="color:#64748b;font-size:13px;margin-top:4px">{html.escape(report.session.provider)} / {html.escape(report.session.model)}</div>
        </div>
        <div style="text-align:right">
          <div class="risk-badge">{html.escape(s.risk_level)}</div>
          <div style="margin-top:8px">
            <span class="score-big">{s.risk_score:.1f}</span>
            <span class="score-denom">/10</span>
          </div>
          <div style="font-size:11px;color:#94a3b8;margin-top:2px">CVSS-style Risk Score</div>
        </div>
      </div>
      <div class="grid4">
        <div class="stat"><div class="stat-n">{s.total_probes}</div><div class="stat-l">Total Probes</div></div>
        <div class="stat"><div class="stat-n" style="color:#dc2626">{s.failed}</div><div class="stat-l">Failed</div></div>
        <div class="stat"><div class="stat-n" style="color:#16a34a">{s.passed}</div><div class="stat-l">Passed</div></div>
        <div class="stat"><div class="stat-n">{s.pass_rate*100:.0f}%</div><div class="stat-l">Pass Rate</div></div>
      </div>
      <div class="grid4" style="margin-top:12px">
        <div class="stat"><div class="stat-n" style="color:#dc2626">{s.critical_findings}</div><div class="stat-l">Critical</div></div>
        <div class="stat"><div class="stat-n" style="color:#ea580c">{s.high_findings}</div><div class="stat-l">High</div></div>
        <div class="stat"><div class="stat-n" style="color:#ca8a04">{s.medium_findings}</div><div class="stat-l">Medium</div></div>
        <div class="stat"><div class="stat-n" style="color:#16a34a">{s.low_findings}</div><div class="stat-l">Low</div></div>
      </div>
    </div>

    <!-- Executive Summary -->
    <div class="card">
      <div class="section-title">Executive Summary</div>
      {exec_summary}
    </div>

    <!-- Findings -->
    <div class="section-title" style="margin-top:8px">Detailed Findings</div>
    {findings_html}

    <!-- Compliance -->
    <div class="card" style="margin-top:24px">
      <div class="section-title">Compliance Assessment</div>
      {compliance_html}
    </div>
  </div>
  <footer>
    Generated by <strong>RedForge</strong> v0.1.0 — Apache 2.0 &nbsp;|&nbsp;
    OWASP LLM Top 10 &nbsp;|&nbsp; MITRE ATLAS &nbsp;|&nbsp; NIST AI RMF &nbsp;|&nbsp; EU AI Act
  </footer>
</body>
</html>"""

    def _render_exec_summary(self, report: ScanReport) -> str:
        s = report.score
        failures = [r for r in report.results if not r.passed]
        failed_owasp = sorted({r.owasp_id for r in failures})

        if not failures:
            return '<div class="no-findings">All probes passed — no vulnerabilities detected in this scan.</div>'

        owasp_list = ", ".join(html.escape(o) for o in failed_owasp)
        lines = [
            f"This assessment identified <strong>{s.failed} failing probe(s)</strong> across "
            f"<strong>{len(failed_owasp)} OWASP LLM category/ies</strong> ({owasp_list}). "
            f"The overall risk score is <strong>{s.risk_score:.1f}/10 ({html.escape(s.risk_level)})</strong>. ",
        ]

        # Dynamically emit severity callouts for any severity level with findings
        from redforge.core.constants import SEVERITY_HEX, SEVERITY_WEIGHTS
        sev_order = sorted(
            s.findings_by_severity.items(),
            key=lambda kv: SEVERITY_WEIGHTS.get(kv[0], 0.5),
            reverse=True,
        )
        for sev, cnt in sev_order:
            color = SEVERITY_HEX.get(sev, "#6b7280")
            if sev == "critical":
                lines.append(
                    f"<strong style='color:{color}'>{cnt} critical finding(s)</strong> require immediate remediation. "
                    "Critical vulnerabilities indicate the model can be manipulated to abandon safety constraints."
                )
            elif sev == "high":
                lines.append(
                    f"<strong style='color:{color}'>{cnt} high-severity finding(s)</strong> should be addressed before production deployment."
                )
            elif cnt > 0:
                lines.append(
                    f"<strong style='color:{color}'>{cnt} {sev}-severity finding(s)</strong> identified."
                )

        lines.append(
            "Prioritize remediating the highest-severity findings first. See per-finding remediation guidance below."
        )
        return f'<div class="exec-box">{"<br>".join(lines)}</div>'

    def _render_findings(self, report: ScanReport) -> str:
        failures = [r for r in report.results if not r.passed]
        if not failures:
            return '<div class="no-findings">All probes passed — no vulnerabilities detected</div>'

        parts = []
        for r in sorted(failures, key=lambda x: x.score, reverse=True):
            color = SEVERITY_COLORS.get(r.severity, "#6b7280")
            bar_width = int(r.score * 100)
            # Probe-level remediation takes priority; fall back to static dict,
            # then to a generic message for categories not yet in the dict.
            remediation = (
                r.remediation
                or _OWASP_REMEDIATION.get(r.owasp_id)
                or f"Review OWASP guidance for {r.owasp_id}. "
                   "Implement appropriate input validation, output filtering, "
                   "and model hardening for this vulnerability class."
            )
            tags_html = " ".join(f'<span class="tag">{html.escape(t)}</span>' for t in r.tags[:5])
            # SECURITY: evidence is our own text — still escaped. Response is NOT rendered.
            parts.append(f"""
    <div class="finding" style="border-color:{color}">
      <div class="finding-header">
        <div>
          <h3>{html.escape(r.probe_id)}</h3>
          <span class="badge" style="background:{color}">{html.escape(r.severity.upper())}</span>
          <span class="badge" style="background:#4b5563">{html.escape(r.owasp_id)}</span>
          <span class="badge" style="background:#1d4ed8">{html.escape(r.mitre_atlas)}</span>
        </div>
        <div style="font-size:20px;font-weight:800;color:{color}">{r.score:.2f}</div>
      </div>
      <div class="score-bar-wrap"><div class="score-bar" style="width:{bar_width}%;background:{color}"></div></div>
      <div style="margin-top:6px">{tags_html}</div>
      <div class="evidence"><strong style="display:block;font-size:11px;text-transform:uppercase;letter-spacing:.5px;color:#6b7280;margin-bottom:4px">Finding</strong>{html.escape(r.evidence)}</div>
      <div class="remediation"><strong>Remediation</strong>{html.escape(remediation)}</div>
    </div>""")
        return "\n".join(parts)

    def _render_compliance(self, report: ScanReport) -> str:
        from redforge.compliance import map_findings_to_compliance
        failures = [r for r in report.results if not r.passed]
        failed_owasp = list({r.owasp_id for r in failures})
        result = map_findings_to_compliance(failed_owasp)

        rows = []
        for v in sorted(result.violations, key=lambda x: x.control_id):
            sev_color = SEVERITY_COLORS.get(v.severity, "#6b7280")
            rows.append(
                f"<tr><td><span class='badge' style='background:#4b5563'>{html.escape(v.framework)}</span></td>"
                f"<td><code>{html.escape(v.control_id)}</code></td>"
                f"<td>{html.escape(v.control_name)}</td>"
                f"<td><span class='fail' style='color:{sev_color}'>{html.escape(v.severity.upper())}</span></td>"
                f"<td style='font-size:11px;color:#374151'>{html.escape(v.remediation[:120])}...</td></tr>"
            )

        table_rows = "\n".join(rows) if rows else "<tr><td colspan='5' style='text-align:center;color:#16a34a;padding:16px'>No compliance violations detected</td></tr>"
        compliance_rate = result.compliance_rate * 100

        return f"""
    <div style="display:flex;gap:20px;margin-bottom:16px;flex-wrap:wrap">
      <div class="stat" style="flex:1;min-width:120px"><div class="stat-n">{compliance_rate:.0f}%</div><div class="stat-l">Compliance Rate</div></div>
      <div class="stat" style="flex:1;min-width:120px"><div class="stat-n" style="color:#dc2626">{len(result.violations)}</div><div class="stat-l">Violations</div></div>
      <div class="stat" style="flex:1;min-width:120px"><div class="stat-n" style="color:#16a34a">{result.compliant_controls}</div><div class="stat-l">Compliant Controls</div></div>
      <div class="stat" style="flex:1;min-width:120px"><div class="stat-n">{result.total_controls}</div><div class="stat-l">Controls Assessed</div></div>
    </div>
    <div style="font-size:11px;color:#64748b;margin-bottom:12px">Frameworks: NIST AI RMF 1.0 &nbsp;·&nbsp; EU AI Act 2024 &nbsp;·&nbsp; ISO/IEC 42001:2023</div>
    <div style="overflow-x:auto">
      <table class="compliance-table">
        <thead><tr><th>Framework</th><th>Control</th><th>Name</th><th>Severity</th><th>Remediation</th></tr></thead>
        <tbody>{table_rows}</tbody>
      </table>
    </div>"""
