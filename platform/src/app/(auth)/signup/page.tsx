"use client";

import { useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { createClient } from "@/lib/supabase/client";

export default function SignupPage() {
  const [fullName, setFullName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [company, setCompany] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const router = useRouter();
  const supabase = createClient();

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);

    const { error } = await supabase.auth.signUp({
      email,
      password,
      options: {
        data: { full_name: fullName, company },
        emailRedirectTo: `${window.location.origin}/api/auth/callback`,
      },
    });

    if (error) {
      setError(error.message);
      setLoading(false);
    } else {
      router.push("/dashboard");
      router.refresh();
    }
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
          <span className="label-caps block mb-2">// Create Account</span>
          <h1 className="font-display text-4xl font-black uppercase tracking-tight leading-none">
            Get Started
          </h1>
          <p className="text-ink-3 text-xs mt-2">
            Start scanning your LLMs for vulnerabilities
          </p>
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label htmlFor="fullName" className="label-caps block mb-1.5">
                Full Name
              </label>
              <input
                id="fullName"
                type="text"
                value={fullName}
                onChange={(e) => setFullName(e.target.value)}
                placeholder="Jane Smith"
                className="input-field"
                required
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
                placeholder="Acme Corp"
                className="input-field"
              />
            </div>
          </div>
          <div>
            <label htmlFor="email" className="label-caps block mb-1.5">
              Work Email
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
              placeholder="Min 8 characters"
              className="input-field"
              required
              minLength={8}
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
            {loading ? "Creating account..." : "Create Account →"}
          </button>
        </form>

        <p className="text-ink-4 text-xs mt-6 text-center">
          Already have an account?{" "}
          <Link
            href="/login"
            className="text-ink underline hover:text-red transition-colors"
          >
            Sign in
          </Link>
        </p>
      </div>
    </div>
  );
}
