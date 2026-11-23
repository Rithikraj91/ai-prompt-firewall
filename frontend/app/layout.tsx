import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "ATTROXX | AI Prompt Injection Firewall & SOC",
  description: "Multi-Tier Defense-in-Depth LLM Security Gateway & Threat Telemetry",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark">
      <body className="antialiased selection:bg-emerald-500/30 selection:text-emerald-200">
        {children}
      </body>
    </html>
  );
}