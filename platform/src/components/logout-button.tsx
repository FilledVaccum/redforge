"use client";

import { useRouter } from "next/navigation";
import { createClient } from "@/lib/supabase/client";

export function LogoutButton() {
  const router = useRouter();
  const supabase = createClient();

  async function handleLogout() {
    await supabase.auth.signOut();
    router.push("/login");
    router.refresh();
  }

  return (
    <button
      onClick={handleLogout}
      className="font-mono text-[9px] tracking-[0.14em] uppercase text-ink-4 hover:text-red transition-colors px-2 py-1 border border-transparent hover:border-ink/[0.12]"
    >
      Sign Out
    </button>
  );
}
