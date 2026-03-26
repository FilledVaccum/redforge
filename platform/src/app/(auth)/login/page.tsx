"use client";

import { useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { createClient } from "@/lib/supabase/client";

export default function LoginPage() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const router = useRouter();
  const supabase = createClient();

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);

    const { error } = await supabase.auth.signInWithPassword({
      email,
      password,
    });

    if (error) {
      setError(error.message);
      setLoading(false);
    } else {
      router.push("/dashboard");
      router.refresh();
    }
  }

  async function handleOAuth(provider: "github" | "google") {
    await supabase.auth.signInWithOAuth({
      provider,
      options: {
        redirectTo: `${window.location.origin}/api/auth/callback`,
      },
    });
  }

  return (
    <div className="min-h-screen bg-paper flex items-center justify-center p-4">
      <div className="w-full max-w-md">
        {/* Logo */}
        <div className="flex items-center gap-2.5 mb-12">
          <div className="w-8 h-8 bg-ink text-paper font-mono text-xs font-semibold flex items-center justify-center">
            RF
          </div>
          <span className="font-display text-lg font-extrabold tracking-wider uppercase">
            RedForge
          </span>
        </div>

        {/* Header */}
        <div className="mb-8">
          <span className="label-caps block mb-2">// Authentication</span>
          <h1 className="font-display text-4xl font-black uppercase tracking-tight leading-none">
            Sign In
          </h1>
          <p className="text-ink-3 text-xs mt-2">
            Access your LLM security dashboard
          </p>
        </div>

        {/* OAuth */}
        <div className="flex gap-2 mb-6">
          <button
            onClick={() => handleOAuth("github")}
            className="btn-outline flex-1 justify-center"
          >
            GitHub
          </button>
          <button
            onClick={() => handleOAuth("google")}
            className="btn-outline flex-1 justify-center"
          >
            Google
          </button>
        </div>

        <div className="flex items-center gap-3 mb-6">
          <div className="h-px flex-1 bg-ink/[0.12]" />
          <span className="label-caps">or</span>
          <div className="h-px flex-1 bg-ink/[0.12]" />
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label htmlFor="email" className="label-caps block mb-1.5">
              Email
            </label>
            <input
              id="email"
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="you@company.com"
              className="input-field"
              required
            />
          </div>
          <div>
            <label htmlFor="password" className="label-caps block mb-1.5">
              Password
            </label>
            <input
              id="password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••"
              className="input-field"
              required
            />
          </div>

          {error && (
            <div className="text-red text-xs font-mono border border-red/20 bg-red/5 px-3 py-2">
              {error}
            </div>
          )}

          <button
            type="submit"
            disabled={loading}
            className="btn-primary w-full justify-center"
          >
            {loading ? "Authenticating..." : "Sign In →"}
          </button>
        </form>

        <p className="text-ink-4 text-xs mt-6 text-center">
          Don&apos;t have an account?{" "}
          <Link
            href="/signup"
            className="text-ink underline hover:text-red transition-colors"
          >
            Create one
          </Link>
        </p>
      </div>
    </div>
  );
}
