"use client";

import { useState, useEffect } from "react";
import { createClient } from "@/lib/supabase/client";

export default function SettingsPage() {
  const supabase = createClient();
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [fullName, setFullName] = useState("");
  const [company, setCompany] = useState("");
  const [message, setMessage] = useState<string | null>(null);

  useEffect(() => {
    async function load() {
      const {
        data: { user },
      } = await supabase.auth.getUser();
      if (user) {
        const { data } = await supabase
          .from("profiles")
          .select("full_name, company")
          .eq("id", user.id)
          .single();
        if (data) {
          setFullName(data.full_name ?? "");
          setCompany(data.company ?? "");
        }
      }
      setLoading(false);
    }
    load();
  }, [supabase]);

  async function handleSave(e: React.FormEvent) {
    e.preventDefault();
    setSaving(true);
    setMessage(null);

    const {
      data: { user },
    } = await supabase.auth.getUser();
    if (!user) return;

    const { error } = await supabase
      .from("profiles")
      .update({ full_name: fullName, company })
      .eq("id", user.id);

    setSaving(false);
    setMessage(error ? error.message : "Settings saved.");
  }

  if (loading) {
    return (
      <div className="font-mono text-xs text-ink-4 animate-pulse">
        Loading settings...
      </div>
    );
  }

  return (
    <div className="max-w-lg">
      <div className="mb-8">
        <span className="label-caps block mb-1">// Account</span>
        <h1 className="font-display text-3xl font-black uppercase tracking-tight">
          Settings
        </h1>
      </div>

      <form onSubmit={handleSave} className="space-y-4">
        <div>
          <label htmlFor="fullName" className="label-caps block mb-1.5">
            Full Name
          </label>
          <input
            id="fullName"
            type="text"
            value={fullName}
            onChange={(e) => setFullName(e.target.value)}
            className="input-field"
          />
        </div>
        <div>
          <label htmlFor="company" className="label-caps block mb-1.5">
            Company
          </label>
          <input
            id="company"
            type="text"
            value={company}
            onChange={(e) => setCompany(e.target.value)}
            className="input-field"
          />
        </div>

        {message && (
          <div className="font-mono text-xs text-ink-3 border border-ink/[0.12] px-3 py-2">
            {message}
          </div>
        )}

        <button type="submit" disabled={saving} className="btn-primary">
          {saving ? "Saving..." : "Save Settings"}
        </button>
      </form>
    </div>
  );
}
