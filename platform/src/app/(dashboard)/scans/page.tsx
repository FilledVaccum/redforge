import Link from "next/link";
import { createClient } from "@/lib/supabase/server";
import { ScanCard } from "@/components/scan-card";

export default async function ScansPage() {
  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();

  const { data: scans } = await supabase
    .from("scans")
    .select("*")
    .eq("user_id", user?.id ?? "")
    .order("created_at", { ascending: false });

  return (
    <div>
      <div className="flex items-center justify-between mb-8">
        <div>
          <span className="label-caps block mb-1">// Scan History</span>
          <h1 className="font-display text-3xl font-black uppercase tracking-tight">
            All Scans
          </h1>
        </div>
        <Link href="/scans/new" className="btn-primary">
          New Scan →
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
            No scans yet.
          </p>
          <Link href="/scans/new" className="btn-primary">
            Launch First Scan →
          </Link>
        </div>
      )}
    </div>
  );
}
