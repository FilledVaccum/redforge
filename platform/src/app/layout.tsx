import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "RedForge Platform — LLM Security Audit Dashboard",
  description:
    "Manage LLM security scans, view vulnerability reports, and track compliance across NIST AI RMF, EU AI Act, and ISO 42001.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className="bg-paper text-ink font-mono text-sm antialiased">
        {children}
      </body>
    </html>
  );
}
