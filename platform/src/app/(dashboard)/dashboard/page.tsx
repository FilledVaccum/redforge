import Link from "next/link";
import { createClient } from "@/lib/supabase/server";
import { RiskGauge } from "@/components/risk-gauge";
import { ScanCard } from "@/components/scan-card";

export default async function DashboardPage() {
  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();

  const { data: profile } = await supabase
    .from("profiles")
    .select("*")
    .eq("id", user?.id ?? "")
    .single();

  const { data: scans } = await supabase
    .from("scans")
    .select("*")
    .eq("user_id", user?.id ?? "")
    .order("created_at", { ascending: false })
    .limit(5);

  const completedScans = scans?.filter((s) => s.status === "completed") ?? [];
  const latestScore =
    completedScans.length > 0 ? completedScans[0].risk_score : null;
  const totalScans = scans?.length ?? 0;
  const totalFindings = completedScans.reduce(
    (sum, s) =>
      sum + s.failed_critical + s.failed_high + s.failed_medium + s.failed_low,
    0,
  );
  const criticalFindings = completedScans.reduce(
    (sum, s) => sum + s.failed_critical,
    0,
  );

  return (
    <div>
      {/* Page header */}
      <div className="flex items-center justify-between mb-8">
        <div>
          <span className="label-caps block mb-1">// Overview</span>
          <h1 className="font-display text-3xl font-black uppercase tracking-tight">
            Dashboard
          </h1>
        </div>
        <Link href="/scans/new" className="btn-primary">
          New Scan →
        </Link>
      </div>

      {/* Stats grid */}
      <div className="grid grid-cols-5 border border-ink/[0.12] mb-8">
        <div className="p-5 border-r border-ink/[0.12] flex items-center justify-center">
          <RiskGauge score={latestScore ? Number(latestScore) : null} />
        </div>
        <div className="p-5 border-r border-ink/[0.12]">
          <span className="font-stat text-4xl leading-none text-ink">
            {totalScans}
          </span>
          <span className="label-caps block mt-1">Total Scans</span>
        </div>
        <div className="p-5 border-r border-ink/[0.12]">
          <span className="font-stat text-4xl leading-none text-ink">
            {totalFindings}
          </span>
          <span className="label-caps block mt-1">Total Findings</span>
        </div>
        <div className="p-5 border-r border-ink/[0.12]">
          <span className="font-stat text-4xl leading-none text-red">
            {criticalFindings}
          </span>
          <span className="label-caps block mt-1">Critical</span>
        </div>
        <div className="p-5">
          <span className="font-stat text-4xl leading-none text-ink">
            {profile?.subscription_tier === "free"
              ? "Free"
              : (profile?.subscription_tier ?? "Free").toUpperCase()}
          </span>
          <span className="label-caps block mt-1">Plan</span>
        </div>
      </div>

      {/* Recent scans */}
      <div className="mb-4 flex items-center justify-between">
        <h2 className="font-display text-xl font-bold uppercase tracking-wide">
          Recent Scans
        </h2>
        <Link
          href="/scans"
          className="font-mono text-[10px] tracking-wide2 uppercase text-ink-3 hover:text-ink transition-colors"
        >
          View All →
        </Link>
      </div>

      {scans && scans.length > 0 ? (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-px bg-ink/[0.06]">
          {scans.map((scan) => (
            <ScanCard key={scan.id} scan={scan} />
          ))}
        </div>
      ) : (
        <div className="border border-ink/[0.12] p-12 text-center">
          <p className="font-mono text-sm text-ink-3 mb-4">
            No scans yet. Run your first LLM security scan.
          </p>
          <Link href="/scans/new" className="btn-primary">
            Launch First Scan →
          </Link>
        </div>
      )}
    </div>
  );
}
