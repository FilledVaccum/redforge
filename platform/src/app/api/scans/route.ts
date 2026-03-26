import { NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";

export async function POST(request: Request) {
  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();

  if (!user) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const body = await request.json();
  const { provider, model, system_prompt, enable_mutations, max_payloads } =
    body;

  if (!provider) {
    return NextResponse.json(
      { error: "Provider is required" },
      { status: 400 },
    );
  }

  // Create the scan record in pending state
  const { data: scan, error } = await supabase
    .from("scans")
    .insert({
      user_id: user.id,
      provider,
      model: model || null,
      system_prompt: system_prompt || null,
      enable_mutations: enable_mutations ?? false,
      max_payloads: max_payloads || null,
      status: "pending",
    })
    .select()
    .single();

  if (error) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }

  // ─── MOCK: Simulate scan execution ──────────────────────────
  // In production, this would dispatch to the RedForge scan engine
  // via the REST API or a background job queue.
  //
  // For now, we simulate by updating the scan to "running" then
  // "completed" with mock results after a short delay.
  //
  // TODO: Replace with real scan execution:
  //   const res = await fetch(`${process.env.REDFORGE_API_URL}/scan`, {
  //     method: "POST",
  //     headers: { "Authorization": `Bearer ${process.env.REDFORGE_API_KEY}` },
  //     body: JSON.stringify({ provider, model, system_prompt, ... }),
  //   });
  // ────────────────────────────────────────────────────────────

  // Fire-and-forget mock simulation
  simulateScan(supabase, scan.id).catch(console.error);

  return NextResponse.json({ scan }, { status: 201 });
}

async function simulateScan(supabase: Awaited<ReturnType<typeof createClient>>, scanId: string) {
  // Mark as running
  await supabase
    .from("scans")
    .update({ status: "running", started_at: new Date().toISOString() })
    .eq("id", scanId);

  // Simulate scan duration (3 seconds)
  await new Promise((r) => setTimeout(r, 3000));

  // Mock results
  const mockFindings = [
    { probe_id: "RF-001", probe_name: "Direct Prompt Injection", owasp_id: "LLM01", severity: "critical" as const, status: "fail" as const, score: 9.1 },
    { probe_id: "RF-007", probe_name: "System Prompt Disclosure", owasp_id: "LLM07", severity: "critical" as const, status: "fail" as const, score: 8.7 },
    { probe_id: "RF-011", probe_name: "DAN Jailbreak", owasp_id: "LLM01", severity: "high" as const, status: "fail" as const, score: 7.4 },
    { probe_id: "RF-013", probe_name: "Roleplay Persona Bypass", owasp_id: "LLM01", severity: "high" as const, status: "fail" as const, score: 7.1 },
    { probe_id: "RF-040", probe_name: "SSRF via URL Injection", owasp_id: "LLM06", severity: "high" as const, status: "fail" as const, score: 6.9 },
    { probe_id: "RF-029", probe_name: "Encoding Bypass (Base64)", owasp_id: "LLM01", severity: "medium" as const, status: "fail" as const, score: 5.2 },
    { probe_id: "RF-030", probe_name: "Multilingual Bypass", owasp_id: "LLM01", severity: "medium" as const, status: "fail" as const, score: 4.9 },
    { probe_id: "RF-002", probe_name: "PII Extraction Attempt", owasp_id: "LLM02", severity: "low" as const, status: "pass" as const, score: 0.8 },
    { probe_id: "RF-003", probe_name: "RAG Poisoning", owasp_id: "LLM03", severity: "low" as const, status: "pass" as const, score: 1.1 },
    { probe_id: "RF-005", probe_name: "Improper Output Handling", owasp_id: "LLM05", severity: "low" as const, status: "pass" as const, score: 1.4 },
  ];

  // Insert findings
  for (const f of mockFindings) {
    await supabase.from("scan_findings").insert({
      scan_id: scanId,
      ...f,
      payload: "[Mock payload — replace with real scan engine]",
      response: "[Mock response — replace with real scan engine]",
      evidence: `Score ${f.score}: ${f.status === "fail" ? "Vulnerability confirmed" : "No vulnerability detected"}`,
    });
  }

  const failures = mockFindings.filter((f) => f.status === "fail") as Array<{ severity: string; status: string }>;

  // Update scan with results
  await supabase
    .from("scans")
    .update({
      status: "completed",
      completed_at: new Date().toISOString(),
      risk_score: 6.8,
      total_probes: 10,
      passed: mockFindings.filter((f) => f.status === "pass").length,
      failed_critical: failures.filter((f) => f.severity === "critical").length,
      failed_high: failures.filter((f) => f.severity === "high").length,
      failed_medium: failures.filter((f) => f.severity === "medium").length,
      failed_low: failures.filter((f) => f.severity === "low").length,
    })
    .eq("id", scanId);
}
