import Stripe from "stripe";

export const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!, {
  apiVersion: "2025-02-24.acacia",
  typescript: true,
});

export const PLANS = {
  starter: {
    name: "Starter Audit",
    price: "$4,900",
    priceId: process.env.STRIPE_PRICE_STARTER!,
    scansIncluded: 1,
    features: [
      "1 LLM endpoint scanned",
      "All 49+ probes executed",
      "OWASP LLM Top 10 coverage report",
      "PDF vulnerability report",
      "Guardrail implementation guide",
      "5 business day turnaround",
      "30-min debrief call",
    ],
  },
  professional: {
    name: "Professional Audit",
    price: "$12,900",
    priceId: process.env.STRIPE_PRICE_PROFESSIONAL!,
    scansIncluded: 3,
    features: [
      "Up to 3 LLM endpoints scanned",
      "All 49+ probes + mutation engine",
      "Compliance gap: NIST + EU AI Act + ISO 42001",
      "Prioritized remediation roadmap",
      "YARA rule templates for every finding",
      "Audit JSONL (full forensic record)",
      "60-min debrief + executive summary",
      "5 business day turnaround",
    ],
  },
  enterprise: {
    name: "Enterprise",
    price: "Custom",
    priceId: process.env.STRIPE_PRICE_ENTERPRISE!,
    scansIncluded: -1,
    features: [
      "Unlimited endpoints",
      "Custom probe development",
      "Continuous automated re-scanning",
      "Multi-model benchmarking",
      "Expert testimony / regulatory support",
      "Dedicated Slack channel",
      "Quarterly security review",
      "Re-scan after remediation",
    ],
  },
} as const;

export type PlanKey = keyof typeof PLANS;
