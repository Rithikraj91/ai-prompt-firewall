"use client";

import React, { useEffect, useMemo, useState } from "react";
import {
  Activity,
  Cpu,
  Download,
  Lock,
  Menu,
  RefreshCw,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Terminal,
  X,
  Zap,
} from "lucide-react";
import AttackLabTab, { type SecurityTelemetry } from "@/components/AttackLabTab";
import LiveTicker from "@/components/LiveTicker";
import { AuditLogsView, TelemetryView } from "@/components/TelemetryAndLogs";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

export default function AttroxxSocDashboard() {
  const [activeTab, setActiveTab] = useState<"lab" | "telemetry" | "logs">("lab");
  const [mobileNavOpen, setMobileNavOpen] = useState<boolean>(false);
  const [backendOnline, setBackendOnline] = useState<boolean>(false);
  const [latestTelemetry, setLatestTelemetry] = useState<SecurityTelemetry | null>(null);
  const [auditLogs, setAuditLogs] = useState<SecurityTelemetry[]>([]);

  const refreshLogs = async () => {
    try {
      const health = await fetch(`${API_BASE}/health`);
      setBackendOnline(health.ok);

      const res = await fetch(`${API_BASE}/v1/audit-logs?limit=100`);
      if (res.ok) {
        const data: SecurityTelemetry[] = await res.json();
        setAuditLogs(data);
        if (data.length > 0 && !latestTelemetry) setLatestTelemetry(data[0]);
      }
    } catch {
      setBackendOnline(false);
    }
  };

  useEffect(() => {
    refreshLogs();

    const evtSource = new EventSource(`${API_BASE}/v1/events/stream`);
    evtSource.onopen = () => setBackendOnline(true);
    evtSource.onmessage = (e) => {
      try {
        const newEvent: SecurityTelemetry = JSON.parse(e.data);
        setAuditLogs((prev) =>
          prev.some((item) => item.id === newEvent.id) ? prev : [newEvent, ...prev]
        );
      } catch {
        // Ignore malformed SSE chunks
      }
    };

    return () => evtSource.close();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const kpis = useMemo(() => {
    const total = auditLogs.length;
    const blocked = auditLogs.filter((l) => l.verdict === "BLOCKED").length;
    const blockRate = total > 0 ? ((blocked / total) * 100).toFixed(1) : "0.0";
    const avgLatency =
      total > 0
        ? (auditLogs.reduce((acc, l) => acc + l.total_latency_ms, 0) / total).toFixed(1)
        : "0.0";
    const recentBlocks = auditLogs.slice(0, 10).filter((l) => l.verdict === "BLOCKED").length;
    const posture = recentBlocks >= 5 ? "ELEVATED" : recentBlocks >= 2 ? "GUARDED" : "NOMINAL";
    return { total, blocked, blockRate, avgLatency, posture };
  }, [auditLogs]);

  const handleExportReport = () => {
    const blob = new Blob([JSON.stringify(auditLogs, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `attroxx-soc-report-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const navItems = [
    { id: "lab", label: "Inspection Lab", sub: "4-Tier X-Ray & RAG", icon: Terminal },
    { id: "telemetry", label: "Threat Analytics", sub: "Taxonomy & Thresholds", icon: Cpu },
    { id: "logs", label: "Incident Ledger", sub: `${auditLogs.length} Audited Events`, icon: ShieldCheck },
  ] as const;

  return (
    <div className="min-h-screen text-slate-200 flex">
      {/* Desktop Left SOC Rail */}
      <aside className="hidden lg:flex w-64 shrink-0 flex-col justify-between border-r border-slate-800/80 bg-[#060a15]/95 backdrop-blur-xl sticky top-0 h-screen p-4">
        <div className="space-y-6">
          <div className="flex items-center gap-3 px-2 pt-1">
            <div className="h-10 w-10 rounded-xl bg-gradient-to-br from-emerald-500/30 via-cyan-500/20 to-slate-900 border border-emerald-400/50 shadow-[0_0_28px_rgba(16,185,129,0.25)] flex items-center justify-center shrink-0">
              <Shield className="w-5 h-5 text-emerald-300" />
            </div>
            <div>
              <h1 className="font-extrabold tracking-[0.2em] text-transparent bg-clip-text bg-gradient-to-r from-white via-emerald-200 to-cyan-300 text-lg">
                ATTROXX
              </h1>
              <span className="text-[10px] font-mono text-cyan-400/80 tracking-widest">
                AI RUNTIME SOC
              </span>
            </div>
          </div>

          <nav className="space-y-1.5">
            <p className="px-2.5 text-[10px] font-mono uppercase tracking-widest text-slate-500 mb-2">
              Operations Console
            </p>
            {navItems.map((item) => {
              const Icon = item.icon;
              const active = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => setActiveTab(item.id)}
                  className={`group w-full flex items-center gap-3 px-3 py-2.5 rounded-xl text-left transition-all duration-200 cursor-pointer ${
                    active
                      ? "bg-gradient-to-r from-emerald-500/20 via-cyan-500/10 to-transparent border border-emerald-400/40 text-white"
                      : "text-slate-400 hover:text-slate-200 hover:bg-slate-900/80 border border-transparent"
                  }`}
                >
                  <div
                    className={`p-1.5 rounded-lg transition ${
                      active
                        ? "bg-emerald-500/20 text-emerald-300"
                        : "bg-slate-900 text-slate-500 group-hover:text-slate-300"
                    }`}
                  >
                    <Icon className="w-4 h-4 shrink-0" />
                  </div>
                  <div>
                    <div className="text-xs font-semibold tracking-wide">{item.label}</div>
                    <div className="text-[10px] font-mono text-slate-500">{item.sub}</div>
                  </div>
                </button>
              );
            })}
          </nav>

          <div className="glass-card rounded-xl border border-slate-800/90 p-3.5 space-y-2.5">
            <div className="flex items-center justify-between">
              <p className="text-[10px] font-mono uppercase tracking-wider text-slate-400">
                Engine Telemetry
              </p>
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-ping" />
            </div>
            {[
              { name: "L0 NFKC + Base64", state: "ACTIVE" },
              { name: "L1 Regex + Entropy", state: "ACTIVE" },
              { name: "L2 Prompt Guard 2", state: "ARMED" },
              { name: "L3 Judge + Canary", state: "SEALED" },
            ].map((tier) => (
              <div key={tier.name} className="flex items-center justify-between text-[11px] font-mono">
                <span className="text-slate-400">{tier.name}</span>
                <span className="text-emerald-400 font-semibold">{tier.state}</span>
              </div>
            ))}
          </div>
        </div>

        <button
          onClick={handleExportReport}
          className="w-full flex items-center justify-center gap-2 px-3 py-2.5 rounded-xl bg-slate-900/90 hover:bg-slate-800 border border-slate-700/80 hover:border-cyan-500/40 text-xs font-mono text-cyan-300 transition cursor-pointer"
        >
          <Download className="w-3.5 h-3.5" />
          Export Audit JSON
        </button>
      </aside>

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0">
        <header className="border-b border-slate-800/80 bg-[#060a15]/85 backdrop-blur-xl sticky top-0 z-30">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 py-3 flex items-center justify-between gap-3">
            <div className="flex items-center gap-3">
              <button
                onClick={() => setMobileNavOpen(!mobileNavOpen)}
                className="lg:hidden p-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-300"
              >
                {mobileNavOpen ? <X className="w-4 h-4" /> : <Menu className="w-4 h-4" />}
              </button>
              <div className="lg:hidden flex items-center gap-2">
                <Shield className="w-4 h-4 text-emerald-400" />
                <span className="font-extrabold tracking-[0.16em] text-white text-sm">ATTROXX</span>
              </div>
              <div className="hidden lg:flex items-center gap-4 text-[11px] font-mono text-slate-400">
                <span>
                  PROXY ENDPOINT: <strong className="text-slate-200">/v1/chat/completions</strong>
                </span>
                <span className="text-slate-700">|</span>
                <span>
                  DEFENSE POSTURE:{" "}
                  <strong
                    className={
                      kpis.posture === "ELEVATED"
                        ? "text-rose-400"
                        : kpis.posture === "GUARDED"
                        ? "text-amber-400"
                        : "text-emerald-400"
                    }
                  >
                    {kpis.posture}
                  </strong>
                </span>
              </div>
            </div>

            <div className="flex items-center gap-2.5">
              <button
                onClick={refreshLogs}
                title="Sync Telemetry"
                className="p-2 rounded-lg bg-slate-900/90 hover:bg-slate-800 border border-slate-800 text-slate-400 hover:text-emerald-300 transition cursor-pointer"
              >
                <RefreshCw className="w-4 h-4" />
              </button>
              <div
                className={`flex items-center gap-2 px-3.5 py-1.5 rounded-full text-xs font-mono border ${
                  backendOnline
                    ? "bg-emerald-500/10 border-emerald-500/35 text-emerald-300"
                    : "bg-rose-500/10 border-rose-500/35 text-rose-300"
                }`}
              >
                <span
                  className={`h-2 w-2 rounded-full ${
                    backendOnline ? "bg-emerald-400 animate-pulse" : "bg-rose-400"
                  }`}
                />
                <span>{backendOnline ? "GATEWAY ONLINE" : "GATEWAY OFFLINE"}</span>
              </div>
            </div>
          </div>

          {mobileNavOpen && (
            <div className="lg:hidden border-t border-slate-800 bg-[#060a15] px-4 py-3 space-y-1.5">
              {navItems.map((item) => {
                const Icon = item.icon;
                return (
                  <button
                    key={item.id}
                    onClick={() => {
                      setActiveTab(item.id);
                      setMobileNavOpen(false);
                    }}
                    className="w-full flex items-center gap-2.5 px-3 py-2 rounded-lg text-xs font-medium text-slate-200 hover:bg-slate-800"
                  >
                    <Icon className="w-4 h-4 text-emerald-400" />
                    {item.label}
                  </button>
                );
              })}
            </div>
          )}
        </header>

        {/* Live Scrolling Event Ticker */}
        <LiveTicker
          events={auditLogs}
          onSelectEvent={(ev) => {
            setLatestTelemetry(ev);
            setActiveTab("lab");
          }}
        />

        <main className="max-w-7xl w-full mx-auto px-4 sm:px-6 py-6 space-y-6 flex-1">
          {/* KPI Strip */}
          <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
            <div className="glass-card border border-slate-800/90 hover:border-sky-500/40 rounded-xl p-4 transition-all duration-200">
              <div className="flex items-center justify-between text-slate-400 text-[11px] font-mono tracking-wider">
                <span>TOTAL INSPECTED</span>
                <Activity className="w-4 h-4 text-sky-400" />
              </div>
              <div className="mt-2 text-2xl sm:text-3xl font-bold text-white font-mono">
                {kpis.total}
              </div>
              <p className="mt-2 text-[11px] font-mono text-slate-500">Chat &amp; RAG payloads</p>
            </div>

            <div className="glass-card border border-slate-800/90 hover:border-rose-500/40 rounded-xl p-4 transition-all duration-200">
              <div className="flex items-center justify-between text-slate-400 text-[11px] font-mono tracking-wider">
                <span>THREATS BLOCKED</span>
                <ShieldAlert className="w-4 h-4 text-rose-400" />
              </div>
              <div className="mt-2 flex items-baseline gap-2">
                <span className="text-2xl sm:text-3xl font-bold text-rose-400 font-mono">
                  {kpis.blocked}
                </span>
                <span className="text-xs font-mono px-1.5 py-0.5 rounded bg-rose-500/10 text-rose-300 border border-rose-500/25">
                  {kpis.blockRate}%
                </span>
              </div>
              <p className="mt-2 text-[11px] font-mono text-slate-500">Zero upstream leakage</p>
            </div>

            <div className="glass-card border border-slate-800/90 hover:border-amber-500/40 rounded-xl p-4 transition-all duration-200">
              <div className="flex items-center justify-between text-slate-400 text-[11px] font-mono tracking-wider">
                <span>MEAN LATENCY</span>
                <Zap className="w-4 h-4 text-amber-400" />
              </div>
              <div className="mt-2 text-2xl sm:text-3xl font-bold text-white font-mono">
                {kpis.avgLatency} <span className="text-sm font-normal text-slate-400">ms</span>
              </div>
              <p className="mt-2 text-[11px] font-mono text-slate-500">L1 short-circuit &lt;1ms</p>
            </div>

            <div className="glass-card border border-slate-800/90 hover:border-emerald-500/40 rounded-xl p-4 transition-all duration-200">
              <div className="flex items-center justify-between text-slate-400 text-[11px] font-mono tracking-wider">
                <span>EGRESS CANARY</span>
                <Lock className="w-4 h-4 text-emerald-400" />
              </div>
              <div className="mt-2 text-2xl sm:text-3xl font-bold text-emerald-400 font-mono">
                SEALED
              </div>
              <p className="mt-2 text-[11px] font-mono text-slate-500">Dynamic session secret</p>
            </div>
          </div>

          {activeTab === "lab" && (
            <AttackLabTab
              apiBase={API_BASE}
              latestTelemetry={latestTelemetry}
              setLatestTelemetry={setLatestTelemetry}
            />
          )}
          {activeTab === "telemetry" && <TelemetryView auditLogs={auditLogs} />}
          {activeTab === "logs" && <AuditLogsView auditLogs={auditLogs} />}
        </main>
      </div>
    </div>
  );
}