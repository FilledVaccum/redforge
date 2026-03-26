"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { PROVIDERS } from "@/lib/types";

const SEVERITY_STYLES: Record<string, string> = {
  critical: "badge-critical",
  high: "badge-high",
  medium: "badge-medium",
  low: "badge-low",
};

const STATUS_STYLES: Record<string, string> = {
  pass: "badge-pass",
  fail: "badge-fail",
};

interface Finding {
  probe_id: string;
  probe_name: string;
  owasp_id: string;
  severity: string;
  status: string;
  score: number;
  evidence: string;
}

interface DemoScan {
  id: string;
  provider: string;
  model: string | null;
  status: string;
  risk_score: number;
  total_probes: number;
  passed: number;
  failed_critical: number;
  failed_high: number;
  failed_medium: number;
  failed_low: number;
  findings: Finding[];
  created_at: string;
}

export default function NewScanPage() {
  const router = useRouter();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [demoResult, setDemoResult] = useState<DemoScan | null>(null);

  const [provider, setProvider] = useState("");
  const [model, setModel] = useState("");
  const [apiKey, setApiKey] = useState("");
  const [endpointUrl, setEndpointUrl] = useState("");
  const [systemPrompt, setSystemPrompt] = useState("");
  const [enableMutations, setEnableMutations] = useState(false);
  const [maxPayloads, setMaxPayloads] = useState<string>("");

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setDemoResult(null);
    setLoading(true);

    try {
      const res = await fetch("/api/scans", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          provider,
          model: model || null,
          api_key: apiKey,
          endpoint_url: endpointUrl || null,
          system_prompt: systemPrompt || null,
          enable_mutations: enableMutations,
          max_payloads: maxPayloads ? parseInt(maxPayloads, 10) : null,
        }),
      });

      if (!res.ok) {
        const data = await res.json();
        throw new Error(data.error || "Failed to create scan");
      }

      const data = await res.json();

      if (data.mode === "demo") {
        // Demo mode — show results inline (no DB to redirect to)
        setDemoResult(data.scan);
        setLoading(false);
      } else {
        // Database mode — redirect to scan detail page
        router.push(`/scans/${data.scan.id}`);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "An error occurred");
      setLoading(false);
    }
  }

  // If we have demo results, show them inline
  if (demoResult) {
    const scan = demoResult;
    const riskColor =
      scan.risk_score >= 7
        ? "text-red"
        : scan.risk_score >= 5
          ? "text-amber-700"
          : scan.risk_score >= 3
            ? "text-yellow-700"
            : "text-green-700";
    const riskLabel =
      scan.risk_score >= 7
        ? "CRITICAL"
        : scan.risk_score >= 5
          ? "HIGH"
          : scan.risk_score >= 3
            ? "MEDIUM"
            : "LOW";

    return (
      <div>
        {/* Demo mode banner */}
        <div className="border border-amber-600/30 bg-amber-600/5 px-4 py-2.5 mb-6 flex items-center gap-3">
          <span className="font-mono text-[9px] font-semibold tracking-caps uppercase text-amber-700">
            // Demo Mode
          </span>
          <span className="font-mono text-[10px] text-amber-700/70">
            Showing simulated results. Connect Supabase for persistent scan history.
          </span>
        </div>

        {/* Header */}
        <div className="flex items-start justify-between mb-8">
          <div>
            <span className="label-caps block mb-1">// Scan Complete</span>
            <h1 className="font-display text-3xl font-black uppercase tracking-tight">
              Scan Results
            </h1>
            <p className="label-caps mt-1">
              {scan.provider}
              {scan.model ? ` / ${scan.model}` : ""} · {scan.id.slice(0, 8)}
            </p>
          </div>
          <div className="w-28 h-28 border-[3px] border-ink rounded-full flex flex-col items-center justify-center flex-shrink-0">
            <span className={`font-stat text-4xl leading-none ${riskColor}`}>
              {scan.risk_score.toFixed(1)}
            </span>
            <span className="font-mono text-[9px] text-ink-4">/ 10.0</span>
            <span
              className={`font-mono text-[8px] font-semibold tracking-caps uppercase ${riskColor} mt-0.5`}
            >
              {riskLabel}
            </span>
          </div>
        </div>

        {/* Stats grid */}
        <div className="grid grid-cols-6 border border-ink/[0.12] mb-6">
          <div className="p-4 border-r border-ink/[0.12] text-center">
            <span className="font-stat text-2xl text-ink">{scan.total_probes}</span>
            <span className="label-caps block mt-0.5">Probes</span>
          </div>
          <div className="p-4 border-r border-ink/[0.12] text-center">
            <span className="font-stat text-2xl text-green-700">{scan.passed}</span>
            <span className="label-caps block mt-0.5">Passed</span>
          </div>
          <div className="p-4 border-r border-ink/[0.12] text-center">
            <span className="font-stat text-2xl text-red">{scan.failed_critical}</span>
            <span className="label-caps block mt-0.5">Critical</span>
          </div>
          <div className="p-4 border-r border-ink/[0.12] text-center">
            <span className="font-stat text-2xl text-amber-700">{scan.failed_high}</span>
            <span className="label-caps block mt-0.5">High</span>
          </div>
          <div className="p-4 border-r border-ink/[0.12] text-center">
            <span className="font-stat text-2xl text-yellow-700">{scan.failed_medium}</span>
            <span className="label-caps block mt-0.5">Medium</span>
          </div>
          <div className="p-4 text-center">
            <span className="font-stat text-2xl text-ink-4">{scan.failed_low}</span>
            <span className="label-caps block mt-0.5">Low</span>
          </div>
        </div>

        {/* Findings table */}
        <div className="border border-ink/[0.12] overflow-hidden mb-6">
          <table className="w-full">
            <thead>
              <tr className="bg-paper-2">
                <th className="label-caps text-left px-4 py-3 border-b border-ink/[0.12]">Probe</th>
                <th className="label-caps text-left px-4 py-3 border-b border-ink/[0.12]">Name</th>
                <th className="label-caps text-left px-4 py-3 border-b border-ink/[0.12]">OWASP</th>
                <th className="label-caps text-left px-4 py-3 border-b border-ink/[0.12]">Severity</th>
                <th className="label-caps text-left px-4 py-3 border-b border-ink/[0.12]">Status</th>
                <th className="label-caps text-left px-4 py-3 border-b border-ink/[0.12]">Score</th>
              </tr>
            </thead>
            <tbody>
              {scan.findings.map((f) => (
                <tr
                  key={f.probe_id}
                  className="border-b border-ink/[0.06] hover:bg-paper-2 transition-colors"
                >
                  <td className="px-4 py-2.5 font-mono text-[11px] text-ink-3">
                    {f.probe_id}
                  </td>
                  <td className="px-4 py-2.5 font-mono text-[11px]">{f.probe_name}</td>
                  <td className="px-4 py-2.5">
                    <span className="badge border-ink-4 text-ink-3">{f.owasp_id}</span>
                  </td>
                  <td className="px-4 py-2.5">
                    <span className={`badge ${SEVERITY_STYLES[f.severity] || ""}`}>
                      {f.severity}
                    </span>
                  </td>
                  <td className="px-4 py-2.5">
                    <span className={`badge ${STATUS_STYLES[f.status] || ""}`}>
                      {f.status}
                    </span>
                  </td>
                  <td className="px-4 py-2.5 font-mono text-[11px]">{f.score.toFixed(1)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Evidence details for failures */}
        <div className="border border-ink/[0.12] mb-6">
          <div className="bg-ink px-4 py-3">
            <span className="font-mono text-[9px] font-semibold tracking-caps uppercase text-red">
              // Finding Evidence
            </span>
          </div>
          {scan.findings
            .filter((f) => f.status === "fail")
            .map((f) => (
              <div
                key={f.probe_id}
                className="px-4 py-3 border-b border-ink/[0.06] last:border-b-0"
              >
                <div className="flex items-center gap-2 mb-1">
                  <span className="font-mono text-[10px] text-ink-3">{f.probe_id}</span>
                  <span className={`badge ${SEVERITY_STYLES[f.severity] || ""}`}>
                    {f.severity}
                  </span>
                </div>
                <p className="font-mono text-[11px] text-ink-2 leading-relaxed">
                  {f.evidence}
                </p>
              </div>
            ))}
        </div>

        {/* Actions */}
        <div className="flex items-center gap-3">
          <button
            onClick={() => setDemoResult(null)}
            className="btn-primary"
          >
            Run Another Scan →
          </button>
          <a
            href="/consulting"
            className="btn-outline"
          >
            Get Full Audit Report →
          </a>
        </div>
      </div>
    );
  }

  // ─── SCAN FORM ──────────────────────────────────────────────
  return (
    <div className="max-w-2xl">
      <div className="mb-8">
        <span className="label-caps block mb-1">// Configure</span>
        <h1 className="font-display text-3xl font-black uppercase tracking-tight">
          New Scan
        </h1>
        <p className="text-ink-3 text-xs mt-2">
          Configure and launch an LLM security scan. All 49+ probes will be
          executed against your endpoint.
        </p>
      </div>

      <form onSubmit={handleSubmit} className="space-y-6">
        {/* Target Configuration */}
        <div className="border border-ink/[0.12] p-5">
          <span className="label-caps block mb-3">
            // Target Configuration
          </span>

          <div className="space-y-4">
            <div>
              <label htmlFor="provider" className="label-caps block mb-1.5">
                LLM Provider *
              </label>
              <select
                id="provider"
                value={provider}
                onChange={(e) => setProvider(e.target.value)}
                className="select-field"
                required
              >
                <option value="" disabled>
                  Select provider
                </option>
                {PROVIDERS.map((p) => (
                  <option key={p.value} value={p.value}>
                    {p.label}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label htmlFor="model" className="label-caps block mb-1.5">
                Model ID
              </label>
              <input
                id="model"
                type="text"
                value={model}
                onChange={(e) => setModel(e.target.value)}
                placeholder="e.g. gpt-4o, claude-sonnet-4-20250514, gemini-pro"
                className="input-field"
              />
            </div>

            <div>
              <label htmlFor="apiKey" className="label-caps block mb-1.5">
                API Key *
              </label>
              <input
                id="apiKey"
                type="password"
                value={apiKey}
                onChange={(e) => setApiKey(e.target.value)}
                placeholder="sk-... or your provider API key"
                className="input-field"
                required
                autoComplete="off"
              />
              <p className="font-mono text-[9px] text-ink-4 mt-1">
                Your API key is used only to execute the scan and is{" "}
                <span className="text-red font-semibold">never stored</span> on
                our servers. Use a scoped key and rotate after testing.
              </p>
            </div>

            {provider === "rest" && (
              <div>
                <label
                  htmlFor="endpointUrl"
                  className="label-caps block mb-1.5"
                >
                  Endpoint URL
                </label>
                <input
                  id="endpointUrl"
                  type="url"
                  value={endpointUrl}
                  onChange={(e) => setEndpointUrl(e.target.value)}
                  placeholder="https://api.your-service.com/v1/chat/completions"
                  className="input-field"
                />
              </div>
            )}

            <div>
              <label
                htmlFor="systemPrompt"
                className="label-caps block mb-1.5"
              >
                System Prompt
              </label>
              <textarea
                id="systemPrompt"
                value={systemPrompt}
                onChange={(e) => setSystemPrompt(e.target.value)}
                placeholder="Paste your system prompt here (optional but recommended — it changes what's exploitable)"
                className="input-field min-h-[120px] resize-y"
                rows={5}
              />
              <p className="font-mono text-[9px] text-ink-4 mt-1">
                Including your system prompt increases scan accuracy — it determines
                which attack vectors are relevant.
              </p>
            </div>
          </div>
        </div>

        {/* Scan Options */}
        <div className="border border-ink/[0.12] p-5">
          <span className="label-caps block mb-3">// Scan Options</span>

          <div className="space-y-4">
            <div className="flex items-center gap-3">
              <input
                type="checkbox"
                id="mutations"
                checked={enableMutations}
                onChange={(e) => setEnableMutations(e.target.checked)}
                className="w-4 h-4 accent-red"
              />
              <label htmlFor="mutations" className="text-sm text-ink-2">
                Enable 37-strategy mutation engine{" "}
                <span className="text-ink-4">(18.5x payload expansion)</span>
              </label>
            </div>

            <div>
              <label htmlFor="maxPayloads" className="label-caps block mb-1.5">
                Max Payloads Per Probe
              </label>
              <input
                id="maxPayloads"
                type="number"
                value={maxPayloads}
                onChange={(e) => setMaxPayloads(e.target.value)}
                placeholder="No limit (default)"
                className="input-field"
                min={1}
              />
            </div>
          </div>
        </div>

        {/* Security Notice */}
        <div className="border border-ink/[0.12] border-l-2 border-l-red bg-red/[0.02] p-4">
          <span className="font-mono text-[9px] font-semibold tracking-caps uppercase text-red block mb-1">
            // Security Notice
          </span>
          <p className="font-mono text-[11px] text-ink-3 leading-relaxed">
            Only scan systems you own or have explicit written authorization to
            test. Your API key is sent over HTTPS directly to the scan engine
            and is never persisted to any database or log. Rotate credentials
            after testing.
          </p>
        </div>

        {error && (
          <div className="text-red text-xs font-mono border border-red/20 bg-red/5 px-3 py-2">
            {error}
          </div>
        )}

        <div className="flex items-center gap-3">
          <button
            type="submit"
            disabled={loading}
            className="btn-primary"
          >
            {loading ? "Initiating scan..." : "Launch Scan →"}
          </button>
          <button
            type="button"
            onClick={() => router.back()}
            className="btn-outline"
          >
            Cancel
          </button>
        </div>
      </form>
    </div>
  );
}
