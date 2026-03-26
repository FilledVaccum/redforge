interface RiskGaugeProps {
  score: number | null;
  size?: "sm" | "md" | "lg";
}

function getRiskLevel(score: number): { label: string; color: string } {
  if (score >= 7) return { label: "CRITICAL", color: "text-red" };
  if (score >= 5) return { label: "HIGH", color: "text-amber-700" };
  if (score >= 3) return { label: "MEDIUM", color: "text-yellow-700" };
  return { label: "LOW", color: "text-green-700" };
}

const SIZES = {
  sm: { outer: "w-16 h-16", score: "text-xl", denom: "text-[8px]", label: "text-[7px]", border: "border-2" },
  md: { outer: "w-24 h-24", score: "text-3xl", denom: "text-[9px]", label: "text-[8px]", border: "border-2" },
  lg: { outer: "w-32 h-32", score: "text-4xl", denom: "text-xs", label: "text-[9px]", border: "border-[3px]" },
};

export function RiskGauge({ score, size = "md" }: RiskGaugeProps) {
  const s = SIZES[size];
  if (score === null) {
    return (
      <div className={`${s.outer} border-ink/20 ${s.border} rounded-full flex flex-col items-center justify-center`}>
        <span className={`font-stat ${s.score} leading-none text-ink-4`}>--</span>
        <span className={`font-mono ${s.label} tracking-caps uppercase text-ink-4 mt-0.5`}>No data</span>
      </div>
    );
  }

  const risk = getRiskLevel(score);

  return (
    <div className={`${s.outer} border-ink ${s.border} rounded-full flex flex-col items-center justify-center`}>
      <span className={`font-stat ${s.score} leading-none ${risk.color}`}>
        {score.toFixed(1)}
      </span>
      <span className={`font-mono ${s.denom} text-ink-4 tracking-wide`}>/ 10.0</span>
      <span className={`font-mono ${s.label} font-semibold tracking-caps uppercase ${risk.color} mt-0.5`}>
        {risk.label}
      </span>
    </div>
  );
}
