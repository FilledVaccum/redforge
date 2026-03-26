// ═══════════════════════════════════════════════════════════════
// Supabase Database types (mirrors the SQL migration)
// ═══════════════════════════════════════════════════════════════

export type Database = {
  public: {
    Tables: {
      profiles: {
        Row: Profile;
        Insert: Partial<Profile> & { id: string };
        Update: Partial<Profile>;
      };
      scans: {
        Row: Scan;
        Insert: ScanInsert;
        Update: Partial<Scan>;
      };
      subscriptions: {
        Row: Subscription;
        Insert: Partial<Subscription>;
        Update: Partial<Subscription>;
      };
      scan_findings: {
        Row: ScanFinding;
        Insert: Partial<ScanFinding> & { scan_id: string; probe_id: string };
        Update: Partial<ScanFinding>;
      };
    };
  };
};

export interface Profile {
  id: string;
  email: string | null;
  full_name: string | null;
  company: string | null;
  role: string | null;
  avatar_url: string | null;
  stripe_customer_id: string | null;
  subscription_tier: "free" | "starter" | "professional" | "enterprise";
  subscription_status: "inactive" | "active" | "canceled" | "past_due";
  scans_used: number;
  scans_limit: number;
  created_at: string;
  updated_at: string;
}

export interface Scan {
  id: string;
  user_id: string;
  provider: string;
  model: string | null;
  endpoint_url: string | null;
  system_prompt: string | null;
  probe_ids: string[] | null;
  enable_mutations: boolean;
  mutation_strategies: string[] | null;
  max_payloads: number | null;
  status: "pending" | "running" | "completed" | "failed" | "canceled";
  risk_score: number | null;
  total_probes: number | null;
  passed: number | null;
  failed_critical: number;
  failed_high: number;
  failed_medium: number;
  failed_low: number;
  results: Record<string, unknown> | null;
  report_url: string | null;
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
}

export type ScanInsert = {
  user_id: string;
  provider: string;
  model?: string | null;
  endpoint_url?: string | null;
  system_prompt?: string | null;
  probe_ids?: string[] | null;
  enable_mutations?: boolean;
  mutation_strategies?: string[] | null;
  max_payloads?: number | null;
};

export interface Subscription {
  id: string;
  user_id: string;
  stripe_subscription_id: string | null;
  stripe_price_id: string | null;
  tier: "starter" | "professional" | "enterprise";
  status: "active" | "canceled" | "past_due" | "incomplete";
  current_period_start: string | null;
  current_period_end: string | null;
  cancel_at_period_end: boolean;
  created_at: string;
  updated_at: string;
}

export interface ScanFinding {
  id: string;
  scan_id: string;
  probe_id: string;
  probe_name: string | null;
  owasp_id: string | null;
  severity: "critical" | "high" | "medium" | "low" | "info" | null;
  status: "pass" | "fail" | null;
  score: number | null;
  payload: string | null;
  response: string | null;
  evidence: string | null;
  created_at: string;
}

// ═══════════════════════════════════════════════════════════════
// UI types
// ═══════════════════════════════════════════════════════════════

export const PROVIDERS = [
  { value: "openai", label: "OpenAI (GPT-4o / GPT-4)" },
  { value: "anthropic", label: "Anthropic (Claude)" },
  { value: "google", label: "Google (Gemini)" },
  { value: "azure", label: "Azure OpenAI" },
  { value: "bedrock", label: "AWS Bedrock" },
  { value: "mistral", label: "Mistral AI" },
  { value: "ollama", label: "Ollama (Local)" },
  { value: "huggingface", label: "HuggingFace Hub" },
  { value: "rest", label: "Generic REST" },
] as const;

export type ScanStatus = Scan["status"];

export const STATUS_COLORS: Record<ScanStatus, string> = {
  pending: "text-ink-4",
  running: "text-amber-600",
  completed: "text-emerald-700",
  failed: "text-red",
  canceled: "text-ink-4",
};
