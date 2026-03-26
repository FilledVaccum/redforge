import { createClient } from "@/lib/supabase/server";
import { LogoutButton } from "./logout-button";

export async function Header() {
  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();

  const { data: profile } = await supabase
    .from("profiles")
    .select("full_name, company, subscription_tier")
    .eq("id", user?.id ?? "")
    .single();

  return (
    <header className="h-12 border-b border-ink/[0.12] bg-paper flex items-center justify-between px-6">
      {/* Classification bar */}
      <div className="flex items-center gap-3">
        <span className="font-mono text-[9px] font-semibold tracking-[0.2em] uppercase text-red">
          Authorized Testing Only
        </span>
        <span className="text-ink-5 text-[10px]">//</span>
        <span className="font-mono text-[9px] tracking-[0.14em] uppercase text-ink-4">
          RedForge Platform
        </span>
      </div>

      {/* User info */}
      <div className="flex items-center gap-4">
        {profile?.subscription_tier && profile.subscription_tier !== "free" && (
          <span className="badge text-[9px] tracking-[0.16em] border-ink-4 text-ink-3">
            {profile.subscription_tier}
          </span>
        )}
        <div className="text-right">
          <div className="font-mono text-[11px] text-ink-2">
            {profile?.full_name || user?.email || "User"}
          </div>
          {profile?.company && (
            <div className="font-mono text-[9px] text-ink-4">
              {profile.company}
            </div>
          )}
        </div>
        <LogoutButton />
      </div>
    </header>
  );
}
