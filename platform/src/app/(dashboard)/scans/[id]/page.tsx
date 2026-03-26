import { notFound } from "next/navigation";
import Link from "next/link";
import { createClient } from "@/lib/supabase/server";
import { RiskGauge } from "@/components/risk-gauge";

export default async function ScanDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  const supabase = await createClient();

  const { data: scan } = await supabase
    .from("scans")
    .select("*")
    .eq("id", id)
    .single();

  if (!scan) notFound();

  const { data: findings } = await supabase
    .from("scan_findings")
    .select("*")
    .eq("scan_id", id)
    .order("score", { ascending: false });

  return (
    <div>
      {/* Breadcrumb + header */}
      <div className="flex items-center gap-2 mb-2">
        <Link
          href="/scans"
          className="font-mono text-[9px] tracking-caps uppercase text-ink-4 hover:text-ink"
        >
          Scans
        </Link>
        <span className="text-ink-5 text-[10px]">/</span>
        <span className="font-mono text-[9px] tracking-caps uppercase text-ink-3">
          {scan.id.slice(0, 8)}
        </span>
      </div>

      <div className="flex items-start justify-between mb-8">
        <div>
          <h1 className="font-display text-3xl font-black uppercase tracking-tight">
            Scan Results
          </h1>
          <p className="label-caps mt-1">
            {scan.provider}
            {scan.model ? ` / ${scan.model}` : ""} · {scan.status}
          </p>
        </div>
        {scan.status === "completed" && (
          <RiskGauge
            score={scan.risk_score ? Number(scan.risk_score) : null}
            size="lg"
          />
        )}
      </div>

      {/* Status states */}
      {scan.status === "pending" && (
        <div className="border border-ink/[0.12] p-8 text-center">
          <div className="font-stat text-5xl text-ink-4 mb-2">PENDING</div>
          <p className="font-mono text-xs text-ink-3">
            Your scan is queued and will start shortly.
          </p>
        </div>
      )}

      {scan.status === "running" && (
        <div className="border border-ink/[0.12] p-8 text-center">
          <div className="font-stat text-5xl text-amber-600 mb-2 animate-pulse">
            SCANNING
          </div>
          <p className="font-mono text-xs text-ink-3">
            Running 49+ probes against your LLM endpoint. This typically takes
            2-10 minutes.
          </p>
        </div>
      )}

      {scan.status === "failed" && (
        <div className="border border-red/20 bg-red/5 p-8 text-center">
          <div className="font-stat text-5xl text-red mb-2">FAILED</div>
          <p className="font-mono text-xs text-ink-3">
            The scan encountered an error. Check your provider credentials and
            try again.
          </p>
        </div>
      )}

      {/* Completed: stats + findings */}
      {scan.status === "completed" && (
        <>
          {/* Summary stats */}
          <div className="grid grid-cols-6 border border-ink/[0.12] mb-6">
            <div className="p-4 border-r border-ink/[0.12] text-center">
              <span className="font-stat text-2xl text-ink">
                {scan.total_probes ?? 0}
              </span>
              <span className="label-caps block mt-0.5">Probes</span>
            </div>
            <div className="p-4 border-r border-ink/[0.12] text-center">
              <span className="font-stat text-2xl text-green-700">
                {scan.passed ?? 0}
              </span>
              <span className="label-caps block mt-0.5">Passed</span>
            </div>
            <div className="p-4 border-r border-ink/[0.12] text-center">
              <span className="font-stat text-2xl text-red">
                {scan.failed_critical}
              </span>
              <span className="label-caps block mt-0.5">Critical</span>
            </div>
            <div className="p-4 border-r border-ink/[0.12] text-center">
              <span className="font-stat text-2xl text-amber-700">
                {scan.failed_high}
              </span>
              <span className="label-caps block mt-0.5">High</span>
            </div>
            <div className="p-4 border-r border-ink/[0.12] text-center">
              <span className="font-stat text-2xl text-yellow-700">
                {scan.failed_medium}
              </span>
              <span className="label-caps block mt-0.5">Medium</span>
            </div>
            <div className="p-4 text-center">
              <span className="font-stat text-2xl text-ink-4">
                {scan.failed_low}
              </span>
              <span className="label-caps block mt-0.5">Low</span>
            </div>
          </div>

          {/* Findings table */}
          {findings && findings.length > 0 && (
            <div className="border border-ink/[0.12] overflow-hidden">
              <table className="w-full">
                <thead>
                  <tr className="bg-paper-2">
                    <th className="label-caps text-left px-4 py-3 border-b border-ink/[0.12]">
                      Probe ID
                    </th>
                    <th className="label-caps text-left px-4 py-3 border-b border-ink/[0.12]">
                      Name
                    </th>
                    <th className="label-caps text-left px-4 py-3 border-b border-ink/[0.12]">
                      OWASP
                    </th>
                    <th className="label-caps text-left px-4 py-3 border-b border-ink/[0.12]">
                      Severity
                    </th>
                    <th className="label-caps text-left px-4 py-3 border-b border-ink/[0.12]">
                      Status
                    </th>
                    <th className="label-caps text-left px-4 py-3 border-b border-ink/[0.12]">
                      Score
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {findings.map((f) => (
                    <tr
                      key={f.id}
                      className="border-b border-ink/[0.06] hover:bg-paper-2 transition-colors"
                    >
                      <td className="px-4 py-2.5 font-mono text-[11px] text-ink-3">
                        {f.probe_id}
                      </td>
                      <td className="px-4 py-2.5 font-mono text-[11px]">
                        {f.probe_name}
                      </td>
                      <td className="px-4 py-2.5">
                        <span className="badge border-ink-4 text-ink-3">
                          {f.owasp_id}
                        </span>
                      </td>
                      <td className="px-4 py-2.5">
                        <span className={`badge badge-${f.severity}`}>
                          {f.severity}
                        </span>
                      </td>
                      <td className="px-4 py-2.5">
                        <span className={`badge badge-${f.status}`}>
                          {f.status}
                        </span>
                      </td>
                      <td className="px-4 py-2.5 font-mono text-[11px]">
                        {f.score?.toFixed(1) ?? "-"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}

      {/* Meta */}
      <div className="mt-8 border-t border-ink/[0.06] pt-4">
        <div className="grid grid-cols-3 gap-4 text-[10px] font-mono text-ink-4">
          <div>
            <span className="block tracking-caps uppercase text-ink-5">
              Scan ID
            </span>
            {scan.id}
          </div>
          <div>
            <span className="block tracking-caps uppercase text-ink-5">
              Created
            </span>
            {new Date(scan.created_at).toLocaleString()}
          </div>
          <div>
            <span className="block tracking-caps uppercase text-ink-5">
              Mutations
            </span>
            {scan.enable_mutations ? "Enabled (37 strategies)" : "Disabled"}
          </div>
        </div>
      </div>
    </div>
  );
}
