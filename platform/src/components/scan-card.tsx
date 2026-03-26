import Link from "next/link";
import type { Scan } from "@/lib/types";
import { STATUS_COLORS } from "@/lib/types";

interface ScanCardProps {
  scan: Scan;
}

export function ScanCard({ scan }: ScanCardProps) {
  const statusColor = STATUS_COLORS[scan.status];

  return (
    <Link
      href={`/scans/${scan.id}`}
      className="block border border-ink/[0.12] hover:bg-paper-2 transition-colors"
    >
      <div className="p-4">
        <div className="flex items-start justify-between mb-3">
          <div>
            <span className="label-caps block mb-1">
              {scan.provider}
              {scan.model ? ` / ${scan.model}` : ""}
            </span>
            <span className={`font-mono text-xs font-semibold tracking-wide2 uppercase ${statusColor}`}>
              {scan.status}
            </span>
          </div>
          {scan.risk_score !== null && (
            <div className="text-right">
              <span className="font-stat text-2xl leading-none text-ink">
                {scan.risk_score.toFixed(1)}
              </span>
              <span className="block font-mono text-[8px] text-ink-4 tracking-wide">
                Risk Score
              </span>
            </div>
          )}
        </div>

        {scan.status === "completed" && (
          <div className="flex gap-3 text-[10px] font-mono tracking-wide">
            {scan.failed_critical > 0 && (
              <span className="text-red">{scan.failed_critical} CRITICAL</span>
            )}
            {scan.failed_high > 0 && (
              <span className="text-amber-700">{scan.failed_high} HIGH</span>
            )}
            {scan.failed_medium > 0 && (
              <span className="text-yellow-700">{scan.failed_medium} MED</span>
            )}
            {scan.passed !== null && (
              <span className="text-green-700">{scan.passed} PASS</span>
            )}
          </div>
        )}

        <div className="mt-3 pt-3 border-t border-ink/[0.06] flex justify-between">
          <span className="font-mono text-[9px] text-ink-4">
            {new Date(scan.created_at).toLocaleDateString("en-US", {
              month: "short",
              day: "numeric",
              year: "numeric",
              hour: "2-digit",
              minute: "2-digit",
            })}
          </span>
          <span className="font-mono text-[9px] text-ink-4">
            {scan.id.slice(0, 8)}
          </span>
        </div>
      </div>
    </Link>
  );
}
