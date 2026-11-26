"use client";

import React, { useCallback, useEffect, useMemo, useState } from "react";
import {
  Activity,
  BarChart3,
  Clock,
  Download,
  FileText,
  Lock,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Terminal,
} from "lucide-react";
import AttackLabTab, { type SecurityTelemetry } from "@/components/AttackLabTab";
import { AuditLogsView, TelemetryView } from "@/components/TelemetryAndLogs";
import LiveTicker from "@/components/LiveTicker";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

interface GatewayPolicy {
  auth_enforced: boolean;
  active_key_count: number;
  failure_mode: string;
  rate_limit_rpm: number;
}

export default function Home() {
  const [activeTab, setActiveTab] = useState<"lab" | "analytics" | "ledger">("lab");
  const [gatewayOnline, setGatewayOnline] = useState<boolean>(false);
  const [policy, setPolicy] = useState<GatewayPolicy | null>(null);
  const [auditLogs, setAuditLogs] = useState<SecurityTelemetry[]>([]);
  const [selectedTelemetry, setSelectedTelemetry] = useState<SecurityTelemetry | null>(null);

  const loadInitialState = useCallback(async () => {
    try {
      const health = await fetch(`${API_BASE}/health`);
      setGatewayOnline(health.ok);
      if (health.ok) {
        const hData = await health.json();
        if (hData.policy) setPolicy(hData.policy);
      }

      const res = await fetch(`${API_BASE}/v1/audit-logs?limit=100`);
      if (res.ok) {
        const data = await res.json();
        const logs: SecurityTelemetry[] = Array.isArray(data) ? data : data.logs || [];
        setAuditLogs(logs);
        if (logs.length > 0) {
          setSelectedTelemetry((prev) => prev ?? logs[0]);
        }
      }
    } catch {
      setGatewayOnline(false);
    }
  }, []);

  useEffect(() => {
    loadInitialState();
    const evtSource = new EventSource(`${API_BASE}/v1/events/stream`);
    evtSource.onmessage = (event) => {
      try {
        const parsed: SecurityTelemetry = JSON.parse(event.data);
        setAuditLogs((prev) =>
          parsed.id && prev.some((item) => item.id === parsed.id)
            ? prev
            : [parsed, ...prev.slice(0, 99)]
        );
      } catch {
        // Ignore keepalive heartbeats
      }
    };
    evtSource.onerror = () => setGatewayOnline(false);
    return () => evtSource.close();
  }, [loadInitialState]);

  const metrics = useMemo(() => {
    const total = auditLogs.length;
    const blocked = auditLogs.filter((l) => l.verdict === "BLOCKED").length;
    const blockRate = total > 0 ? ((blocked / total) * 100).toFixed(1) : "0.0";
    const meanLatency =
      total > 0
        ? (
            auditLogs.reduce((acc, l) => acc + (l.total_latency_ms || 0), 0) / total
          ).toFixed(1)
        : "0.0";
    return { total, blocked, blockRate, meanLatency };
  }, [auditLogs]);

  const handleExportJson = () => {
    const blob = new Blob([JSON.stringify(auditLogs, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `attroxx-audit-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="min-h-screen bg-[#080c10] text-slate-100 flex">
      {/* Sidebar */}
      <aside className="w-72 border-r border-slate-800 bg-[#0c141b] flex flex-col justify-between shrink-0">
        <div>
          {/* Prominent Brand Header */}
          <div className="px-6 py-6 border-b border-slate-800 flex items-center gap-3.5">
            <div className="w-11 h-11 rounded-2xl bg-emerald-600/20 border border-emerald-500/40 flex items-center justify-center shadow-[0_0_16px_rgba(16,185,129,0.2)]">
              <Shield className="w-5 h-5 text-emerald-400" />
            </div>
            <div>
              <div className="text-2xl font-black tracking-[0.22em] bg-gradient-to-r from-white via-emerald-200 to-emerald-400 bg-clip-text text-transparent drop-shadow-[0_0_12px_rgba(16,185,129,0.45)]">
                ATTROXX
              </div>
              <div className="text-[10px] font-mono uppercase tracking-[0.18em] text-emerald-400/80 mt-0.5">
                RUNTIME AI FIREWALL
              </div>
            </div>
          </div>

          {/* Primary Navigation */}
          <nav className="p-4 space-y-1.5">
            <div className="px-3 py-1.5 text-xs font-semibold uppercase tracking-wider text-slate-500">
              SOC Console
            </div>

            <button
              onClick={() => setActiveTab("lab")}
              className={`w-full flex items-center gap-3 px-3.5 py-2.5 rounded-lg text-sm font-medium transition-colors cursor-pointer ${
                activeTab === "lab"
                  ? "bg-emerald-600/15 text-white border border-emerald-500/30"
                  : "text-slate-400 hover:text-slate-100 hover:bg-slate-800/60"
              }`}
            >
              <Terminal
                className={`w-4 h-4 ${
                  activeTab === "lab" ? "text-emerald-400" : "text-slate-400"
                }`}
              />
              Inspection Lab
            </button>

            <button
              onClick={() => setActiveTab("analytics")}
              className={`w-full flex items-center gap-3 px-3.5 py-2.5 rounded-lg text-sm font-medium transition-colors cursor-pointer ${
                activeTab === "analytics"
                  ? "bg-emerald-600/15 text-white border border-emerald-500/30"
                  : "text-slate-400 hover:text-slate-100 hover:bg-slate-800/60"
              }`}
            >
              <BarChart3
                className={`w-4 h-4 ${
                  activeTab === "analytics" ? "text-emerald-400" : "text-slate-400"
                }`}
              />
              Threat & Benchmark Analytics
            </button>

            <button
              onClick={() => setActiveTab("ledger")}
              className={`w-full flex items-center justify-between px-3.5 py-2.5 rounded-lg text-sm font-medium transition-colors cursor-pointer ${
                activeTab === "ledger"
                  ? "bg-emerald-600/15 text-white border border-emerald-500/30"
                  : "text-slate-400 hover:text-slate-100 hover:bg-slate-800/60"
              }`}
            >
              <span className="flex items-center gap-3">
                <FileText
                  className={`w-4 h-4 ${
                    activeTab === "ledger" ? "text-emerald-400" : "text-slate-400"
                  }`}
                />
                Incident Ledger
              </span>
              <span className="text-xs font-mono px-2 py-0.5 rounded-full bg-slate-800 text-slate-300">
                {auditLogs.length}
              </span>
            </button>
          </nav>

          {/* Upgraded 4-Tier Defense Layer Cards */}
          <div className="px-4 py-4 mt-1 border-t border-slate-800/80 space-y-3">
            <div className="flex items-center justify-between px-1">
              <span className="text-xs font-bold uppercase tracking-[0.15em] text-slate-400">
                Defense Layers
              </span>
              <span className="text-[11px] font-mono text-emerald-400/80">
                4-TIER
              </span>
            </div>

            <div className="space-y-2.5">
              {[
                {
                  code: "L0",
                  name: "Input Normalizer",
                  desc: "NFKC, homoglyph & Base64",
                  status: "Active",
                  active: true,
                },
                {
                  code: "L1",
                  name: "Regex & Entropy",
                  desc: "Deterministic < 0.2 ms",
                  status: "Active",
                  active: true,
                },
                {
                  code: "L2",
                  name: "Prompt Guard 2",
                  desc: "Semantic ML + LRU cache",
                  status: "Active",
                  active: true,
                },
                {
                  code: "L3",
                  name: "Judge & Canary",
                  desc: "Deep review & egress lock",
                  status: "Armed",
                  active: false,
                },
              ].map((layer) => (
                <div
                  key={layer.code}
                  className="p-3 rounded-xl bg-[#080c10]/95 border border-slate-800/90 hover:border-emerald-500/35 transition-all flex items-center justify-between gap-2.5"
                >
                  <div className="flex items-center gap-2.5 min-w-0">
                    <span
                      className={`w-8 h-8 rounded-lg font-mono text-xs font-extrabold flex items-center justify-center shrink-0 border ${
                        layer.active
                          ? "bg-emerald-500/15 text-emerald-300 border-emerald-500/30 shadow-[0_0_10px_rgba(16,185,129,0.18)]"
                          : "bg-amber-500/15 text-amber-300 border-amber-500/30"
                      }`}
                    >
                      {layer.code}
                    </span>
                    <div className="min-w-0">
                      <div className="text-sm font-semibold text-slate-100 truncate">
                        {layer.name}
                      </div>
                      <div className="text-[11px] text-slate-400 truncate">
                        {layer.desc}
                      </div>
                    </div>
                  </div>

                  <span
                    className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md text-[11px] font-mono font-semibold shrink-0 ${
                      layer.active
                        ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/25"
                        : "bg-amber-500/10 text-amber-400 border border-amber-500/25"
                    }`}
                  >
                    <span
                      className={`w-1.5 h-1.5 rounded-full ${
                        layer.active ? "bg-emerald-400 animate-pulse" : "bg-amber-400"
                      }`}
                    />
                    {layer.status}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>

        <div className="p-4 border-t border-slate-800">
          <button
            onClick={handleExportJson}
            className="w-full flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg text-sm font-medium bg-[#0b1117] hover:bg-slate-800 text-slate-200 border border-slate-800/80 transition-colors cursor-pointer"
          >
            <Download className="w-4 h-4 text-emerald-400" />
            Export Audit JSON
          </button>
        </div>
      </aside>

      {/* Main Content */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Top Bar with Gateway Hardening Posture */}
        <header className="h-16 px-6 lg:px-8 border-b border-slate-800 bg-[#0c141b] flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-3 text-sm">
            <span className="text-slate-400 font-medium">Proxy Endpoint</span>
            <code className="px-3 py-1 rounded-md bg-[#0b1117] border border-slate-800 text-emerald-300 font-mono text-xs">
              POST /v1/chat/completions
            </code>
          </div>

          <div className="flex items-center gap-2.5">
            {policy && (
              <>
                <span className="hidden md:inline-flex items-center gap-1.5 text-[11px] font-mono px-2.5 py-1 rounded-md bg-[#0b1117] border border-slate-800 text-cyan-300">
                  <ShieldCheck className="w-3.5 h-3.5 text-cyan-400" />
                  {policy.failure_mode.toUpperCase()}
                </span>
                <span className="hidden lg:inline-flex items-center gap-1.5 text-[11px] font-mono px-2.5 py-1 rounded-md bg-[#0b1117] border border-slate-800 text-slate-300">
                  {policy.rate_limit_rpm} RPM · PII/KEY REDACT
                </span>
              </>
            )}

            <div className="flex items-center gap-2.5 text-xs font-semibold px-3.5 py-1.5 rounded-full bg-[#0b1117] border border-slate-800">
              <span
                className={`w-2.5 h-2.5 rounded-full ${
                  gatewayOnline ? "bg-emerald-400 animate-pulse" : "bg-rose-500"
                }`}
              />
              <span className="text-slate-200">
                {gatewayOnline ? "Gateway Online" : "Gateway Offline"}
              </span>
            </div>
          </div>
        </header>

        {/* Live Ticker */}
        <LiveTicker
          events={auditLogs}
          onSelectEvent={(ev) => {
            setSelectedTelemetry(ev);
            setActiveTab("lab");
          }}
        />

        {/* Full-Width Workspace Body */}
        <main className="flex-1 p-6 lg:p-8 w-full space-y-6">
          {/* 4 Bold KPI Cards */}
          <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-5">
            <div className="p-5 rounded-2xl bg-[#101820] border border-slate-800 border-l-4 border-l-emerald-500">
              <div className="flex items-center justify-between text-sm font-medium text-slate-400">
                <span>Total Inspected</span>
                <Activity className="w-4 h-4 text-emerald-400" />
              </div>
              <div className="mt-2.5 text-3xl font-bold tracking-tight text-white">
                {metrics.total}
              </div>
              <div className="mt-1 text-[10px] font-mono uppercase tracking-[0.18em] text-emerald-400/80">
                Chat & RAG payloads scanned
              </div>
            </div>

            <div className="p-5 rounded-2xl bg-[#101820] border border-slate-800 border-l-4 border-l-rose-500">
              <div className="flex items-center justify-between text-sm font-medium text-slate-400">
                <span>Threats Blocked</span>
                <span className="inline-flex items-center gap-1 text-xs font-mono font-semibold px-2 py-0.5 rounded bg-rose-500/15 text-rose-400">
                  <ShieldAlert className="w-3.5 h-3.5" />
                  {metrics.blockRate}%
                </span>
              </div>
              <div className="mt-2.5 text-3xl font-bold tracking-tight text-white">
                {metrics.blocked}
              </div>
              <div className="mt-1 text-xs text-slate-400">
                Zero upstream model leakage
              </div>
            </div>

            <div className="p-5 rounded-2xl bg-[#101820] border border-slate-800 border-l-4 border-l-amber-500">
              <div className="flex items-center justify-between text-sm font-medium text-slate-400">
                <span>Mean Latency</span>
                <Clock className="w-4 h-4 text-amber-400" />
              </div>
              <div className="mt-2.5 flex items-baseline gap-1.5">
                <span className="text-3xl font-bold tracking-tight text-white">
                  {metrics.meanLatency}
                </span>
                <span className="text-sm text-slate-400 font-mono">ms</span>
              </div>
              <div className="mt-1 text-xs text-slate-400">
                L1 deterministic &lt; 0.2 ms
              </div>
            </div>

            <div className="p-5 rounded-2xl bg-[#101820] border border-slate-800 border-l-4 border-l-emerald-500">
              <div className="flex items-center justify-between text-sm font-medium text-slate-400">
                <span>Egress Canary</span>
                <Lock className="w-4 h-4 text-emerald-400" />
              </div>
              <div className="mt-2.5 text-3xl font-bold tracking-tight text-emerald-400">
                Sealed
              </div>
              <div className="mt-1 text-xs text-slate-400">
                Dynamic session secret active
              </div>
            </div>
          </div>

          {/* Active View */}
          {activeTab === "lab" && (
            <AttackLabTab
              apiBase={API_BASE}
              initialTelemetry={selectedTelemetry}
              onNewTelemetry={(t) => {
                setSelectedTelemetry(t);
                setAuditLogs((prev) =>
                  t.id && prev.some((item) => item.id === t.id)
                    ? prev
                    : [t, ...prev.slice(0, 99)]
                );
              }}
            />
          )}

          {activeTab === "analytics" && (
            <TelemetryView auditLogs={auditLogs} apiBase={API_BASE} />
          )}

          {activeTab === "ledger" && (
            <AuditLogsView
              auditLogs={auditLogs}
              onSelectLog={(ev) => {
                setSelectedTelemetry(ev);
                setActiveTab("lab");
              }}
            />
          )}
        </main>
      </div>
    </div>
  );
}
