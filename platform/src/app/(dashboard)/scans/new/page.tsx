"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { PROVIDERS } from "@/lib/types";

export default function NewScanPage() {
  const router = useRouter();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [provider, setProvider] = useState("");
  const [model, setModel] = useState("");
  const [systemPrompt, setSystemPrompt] = useState("");
  const [enableMutations, setEnableMutations] = useState(false);
  const [maxPayloads, setMaxPayloads] = useState<string>("");

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      const res = await fetch("/api/scans", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          provider,
          model: model || null,
          system_prompt: systemPrompt || null,
          enable_mutations: enableMutations,
          max_payloads: maxPayloads ? parseInt(maxPayloads, 10) : null,
        }),
      });

      if (!res.ok) {
        const data = await res.json();
        throw new Error(data.error || "Failed to create scan");
      }

      const { scan } = await res.json();
      router.push(`/scans/${scan.id}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "An error occurred");
      setLoading(false);
    }
  }

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
        {/* Provider */}
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
                Your system prompt is used only during the scan and is never
                stored on our servers.
              </p>
            </div>
          </div>
        </div>

        {/* Scan options */}
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

        {/* Security notice */}
        <div className="border border-ink/[0.12] border-l-2 border-l-red bg-red/[0.02] p-4">
          <span className="font-mono text-[9px] font-semibold tracking-caps uppercase text-red block mb-1">
            // Security Notice
          </span>
          <p className="font-mono text-[11px] text-ink-3 leading-relaxed">
            Only scan systems you own or have explicit written authorization to
            test. Your API credentials are used ephemeral during the scan and
            are never persisted. Rotate credentials after testing.
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
