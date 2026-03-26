"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

const NAV_ITEMS = [
  {
    label: "Dashboard",
    href: "/dashboard",
    icon: "◉",
  },
  {
    label: "Scans",
    href: "/scans",
    icon: "⬡",
  },
  {
    label: "New Scan",
    href: "/scans/new",
    icon: "+",
  },
  {
    label: "Billing",
    href: "/billing",
    icon: "⊞",
  },
  {
    label: "Settings",
    href: "/settings",
    icon: "⚙",
  },
];

export function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className="w-56 h-screen bg-ink flex flex-col border-r border-ink-2 fixed left-0 top-0 z-50">
      {/* Logo */}
      <div className="px-5 py-5 border-b border-white/[0.06]">
        <Link href="/dashboard" className="flex items-center gap-2.5">
          <div className="w-7 h-7 bg-red text-white font-mono text-[10px] font-semibold flex items-center justify-center">
            RF
          </div>
          <span className="font-display text-sm font-extrabold tracking-wider uppercase text-paper">
            RedForge
          </span>
        </Link>
        <div className="font-mono text-[9px] tracking-[0.2em] uppercase text-ink-3 mt-1.5">
          Security Platform
        </div>
      </div>

      {/* Nav */}
      <nav className="flex-1 py-4 px-3 space-y-0.5">
        {NAV_ITEMS.map((item) => {
          const isActive =
            pathname === item.href ||
            (item.href !== "/dashboard" && pathname.startsWith(item.href));
          return (
            <Link
              key={item.href}
              href={item.href}
              className={`flex items-center gap-3 px-3 py-2.5 text-[11px] font-mono tracking-[0.12em] uppercase transition-colors ${
                isActive
                  ? "text-paper bg-white/[0.06]"
                  : "text-ink-4 hover:text-ink-5 hover:bg-white/[0.03]"
              }`}
            >
              <span
                className={`text-xs ${isActive ? "text-red" : "text-ink-3"}`}
              >
                {item.icon}
              </span>
              {item.label}
            </Link>
          );
        })}
      </nav>

      {/* Footer */}
      <div className="px-5 py-4 border-t border-white/[0.06]">
        <div className="font-mono text-[9px] tracking-[0.14em] uppercase text-ink-3">
          v0.5.0 · Apache 2.0
        </div>
        <Link
          href="https://redforge.vercel.app"
          target="_blank"
          className="font-mono text-[9px] tracking-[0.1em] text-ink-4 hover:text-ink-5 transition-colors"
        >
          redforge.vercel.app →
        </Link>
      </div>
    </aside>
  );
}
