import { createClient } from "@/lib/supabase/server";
import { PLANS } from "@/lib/stripe";

export default async function BillingPage() {
  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();

  const { data: profile } = await supabase
    .from("profiles")
    .select("subscription_tier, subscription_status, stripe_customer_id")
    .eq("id", user?.id ?? "")
    .single();

  const { data: subscription } = await supabase
    .from("subscriptions")
    .select("*")
    .eq("user_id", user?.id ?? "")
    .eq("status", "active")
    .single();

  const currentTier = profile?.subscription_tier ?? "free";

  return (
    <div>
      <div className="mb-8">
        <span className="label-caps block mb-1">// Billing</span>
        <h1 className="font-display text-3xl font-black uppercase tracking-tight">
          Plans & Billing
        </h1>
      </div>

      {/* Current plan */}
      <div className="border border-ink/[0.12] p-5 mb-8">
        <span className="label-caps block mb-2">// Current Plan</span>
        <div className="flex items-center gap-4">
          <span className="font-stat text-4xl text-ink">
            {currentTier.toUpperCase()}
          </span>
          {subscription && (
            <div className="text-[10px] font-mono text-ink-4">
              <div>
                Status: <span className="text-green-700">{subscription.status}</span>
              </div>
              {subscription.current_period_end && (
                <div>
                  Renews:{" "}
                  {new Date(subscription.current_period_end).toLocaleDateString()}
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      {/* Plan cards */}
      <div className="grid grid-cols-3 gap-px bg-ink/[0.06]">
        {(Object.entries(PLANS) as [string, (typeof PLANS)[keyof typeof PLANS]][]).map(
          ([key, plan]) => {
            const isCurrentPlan = currentTier === key;
            return (
              <div
                key={key}
                className={`p-6 ${
                  key === "professional"
                    ? "bg-ink text-paper"
                    : "bg-paper"
                }`}
              >
                {key === "professional" && (
                  <span className="inline-block font-mono text-[8px] font-semibold tracking-caps uppercase bg-red text-white px-2 py-0.5 mb-3">
                    Most Popular
                  </span>
                )}
                <span
                  className={`label-caps block mb-1 ${
                    key === "professional" ? "text-ink-4" : ""
                  }`}
                >
                  // {key}
                </span>
                <div className="font-stat text-4xl leading-none mb-1">
                  {plan.price}
                </div>
                <p
                  className={`text-[11px] mb-4 ${
                    key === "professional" ? "text-ink-4" : "text-ink-3"
                  }`}
                >
                  {plan.scansIncluded > 0
                    ? `${plan.scansIncluded} scan${plan.scansIncluded > 1 ? "s" : ""} included`
                    : "Unlimited scans"}
                </p>

                <div
                  className={`border-t pt-4 mb-4 ${
                    key === "professional"
                      ? "border-white/10"
                      : "border-ink/[0.12]"
                  }`}
                >
                  <ul className="space-y-2">
                    {plan.features.map((f) => (
                      <li
                        key={f}
                        className={`text-[11px] flex gap-2 ${
                          key === "professional" ? "text-ink-4" : "text-ink-3"
                        }`}
                      >
                        <span className="text-green-600 flex-shrink-0">
                          ✓
                        </span>
                        {f}
                      </li>
                    ))}
                  </ul>
                </div>

                {isCurrentPlan ? (
                  <span className="btn-outline w-full justify-center pointer-events-none opacity-50">
                    Current Plan
                  </span>
                ) : (
                  <form action="/api/stripe/checkout" method="POST">
                    <input type="hidden" name="tier" value={key} />
                    <button
                      type="submit"
                      className={`w-full justify-center ${
                        key === "professional" ? "btn-primary bg-red border-red hover:bg-red-dark" : "btn-primary"
                      }`}
                    >
                      {plan.price === "Custom"
                        ? "Contact Sales →"
                        : `Upgrade to ${plan.name} →`}
                    </button>
                  </form>
                )}
              </div>
            );
          },
        )}
      </div>
    </div>
  );
}
