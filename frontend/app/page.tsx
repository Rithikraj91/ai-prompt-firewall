"use client";

import React, { useCallback, useEffect, useMemo, useState } from "react";
import {
  Activity,
  BarChart3,
  Clock,
  Download,
  FileText,
  Lock,
  ShieldAlert,
  ShieldCheck,
  Terminal,
} from "lucide-react";
import AttackLabTab, { type SecurityTelemetry } from "@/components/AttackLabTab";
import { AuditLogsView, TelemetryView } from "@/components/TelemetryAndLogs";
import LiveTicker from "@/components/LiveTicker";
import { AttroxxLogo } from "../components/AttroxxLogo";

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

  const navItemClass = (active: boolean) =>
    `relative flex shrink-0 items-center gap-2.5 whitespace-nowrap rounded-xl border px-3 py-2 text-left text-sm font-medium cursor-pointer lg:w-full lg:whitespace-normal ${
      active
        ? "border-emerald-400/35 bg-gradient-to-r from-emerald-500/15 via-emerald-500/8 to-transparent text-white shadow-[inset_0_1px_0_rgba(110,231,183,0.12)]"
        : "border-transparent text-slate-400 hover:border-slate-800 hover:bg-white/[0.025] hover:text-slate-100"
    }`;

  return (
    <div className="flex min-h-screen flex-col text-slate-100 lg:h-screen lg:flex-row lg:overflow-hidden">
      <aside className="flex w-full shrink-0 flex-col border-b border-slate-800/80 bg-[#090e17]/95 backdrop-blur-md lg:h-screen lg:w-[284px] lg:overflow-y-auto lg:border-b-0 lg:border-r">
        <div>
          <div className="border-b border-slate-800/80 p-3">
            <AttroxxLogo />
          </div>

          <nav className="px-3 py-2.5">
            <div className="flex items-center justify-between px-2.5 pb-1.5">
              <span className="font-mono text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-500">
                SOC Console
              </span>
              <span className="font-mono text-[10px] text-slate-600">GATEWAY</span>
            </div>

            <div className="flex gap-1.5 overflow-x-auto lg:flex-col lg:overflow-visible">
              <button
                onClick={() => setActiveTab("lab")}
                className={navItemClass(activeTab === "lab")}
              >
                {activeTab === "lab" && (
                  <span className="hidden lg:block absolute left-0 top-2 bottom-2 w-0.5 rounded-r bg-emerald-400 shadow-[0_0_8px_#10b981]" />
                )}
                <Terminal
                  className={`h-4 w-4 shrink-0 ${
                    activeTab === "lab" ? "text-emerald-400" : "text-slate-500"
                  }`}
                />
                <span>Inspection Lab</span>
              </button>

              <button
                onClick={() => setActiveTab("analytics")}
                className={navItemClass(activeTab === "analytics")}
              >
                {activeTab === "analytics" && (
                  <span className="hidden lg:block absolute left-0 top-2 bottom-2 w-0.5 rounded-r bg-emerald-400 shadow-[0_0_8px_#10b981]" />
                )}
                <BarChart3
                  className={`h-4 w-4 shrink-0 ${
                    activeTab === "analytics" ? "text-emerald-400" : "text-slate-500"
                  }`}
                />
                <span>Threat &amp; Benchmark Analytics</span>
              </button>

              <button
                onClick={() => setActiveTab("ledger")}
                className={`${navItemClass(activeTab === "ledger")} justify-between`}
              >
                {activeTab === "ledger" && (
                  <span className="hidden lg:block absolute left-0 top-2 bottom-2 w-0.5 rounded-r bg-emerald-400 shadow-[0_0_8px_#10b981]" />
                )}
                <span className="flex items-center gap-2.5">
                  <FileText
                    className={`h-4 w-4 shrink-0 ${
                      activeTab === "ledger" ? "text-emerald-400" : "text-slate-500"
                    }`}
                  />
                  <span>Incident Ledger</span>
                </span>
                <span className="rounded-md border border-slate-700/80 bg-[#070b13] px-2 py-0.5 font-mono text-[11px] font-semibold text-slate-300 tabular-nums">
                  {auditLogs.length}
                </span>
              </button>
            </div>
          </nav>

          {/* 4-Tier Defense Layer Cards */}
          <div className="space-y-2.5 border-t border-slate-800/80 px-3 py-3">
            <div className="flex items-center justify-between px-1">
              <span className="font-mono text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-500">
                Defense Layers
              </span>
              <span className="rounded border border-emerald-500/25 bg-emerald-500/10 px-1.5 py-0.5 font-mono text-[10px] font-semibold text-emerald-300">
                4-TIER
              </span>
            </div>

            <div className="grid gap-1.5 sm:grid-cols-2 lg:grid-cols-1">
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
                  className="attroxx-well flex items-center justify-between gap-2 rounded-xl border border-slate-800/90 px-2.5 py-2 hover:border-emerald-500/35"
                >
                  <div className="flex min-w-0 items-center gap-2">
                    <span
                      className={`flex h-7 w-7 shrink-0 items-center justify-center rounded-lg border font-mono text-[11px] font-bold ${
                        layer.active
                          ? "border-emerald-500/35 bg-emerald-500/15 text-emerald-300 shadow-[0_0_12px_rgba(16,185,129,0.16)]"
                          : "border-amber-500/35 bg-amber-500/15 text-amber-300"
                      }`}
                    >
                      {layer.code}
                    </span>
                    <div className="min-w-0">
                      <div className="truncate text-[13px] font-semibold leading-tight text-slate-100">
                        {layer.name}
                      </div>
                      <div className="mt-0.5 truncate text-[11px] leading-tight text-slate-400">
                        {layer.desc}
                      </div>
                    </div>
                  </div>

                  <span
                    className={`inline-flex shrink-0 items-center gap-1.5 rounded-md border px-2 py-0.5 font-mono text-[10px] font-semibold ${
                      layer.active
                        ? "border-emerald-500/25 bg-emerald-500/10 text-emerald-300"
                        : "border-amber-500/25 bg-amber-500/10 text-amber-300"
                    }`}
                  >
                    <span
                      className={`h-1.5 w-1.5 rounded-full ${
                        layer.active ? "bg-emerald-400 animate-pulse" : "bg-amber-400"
                      }`}
                    />
                    {layer.status}
                  </span>
                </div>
              ))}
            </div>

            {/* Gateway Hardening Posture Card */}
            <div className="space-y-2 border-t border-slate-800/80 pt-2.5">
              <div className="flex items-center justify-between px-1">
                <span className="font-mono text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-500">
                  Gateway Posture
                </span>
                <span className="font-mono text-[10px] font-semibold tracking-wider text-cyan-300">
                  HARDENED
                </span>
              </div>

              <div className="attroxx-well space-y-1.5 rounded-xl border border-slate-800/90 px-3 py-2.5 text-xs">
                <div className="flex items-center justify-between">
                  <span className="text-slate-400">Failure Policy</span>
                  <span className="font-mono font-semibold text-cyan-300">
                    {policy ? policy.failure_mode.toUpperCase() : "FAIL_CLOSED"}
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-slate-400">Burst Guard</span>
                  <span className="font-mono text-slate-200 tabular-nums">
                    {policy ? `${policy.rate_limit_rpm} RPM` : "120 RPM"}
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-slate-400">Log Redaction</span>
                  <span className="font-mono text-emerald-400">Keys &amp; Canary</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-slate-400">RAG Chunking</span>
                  <span className="font-mono text-slate-200">450c / 150 overlap</span>
                </div>
              </div>
            </div>
          </div>
        </div>

        <div className="mt-auto border-t border-slate-800/80 p-3">
          <button
            onClick={handleExportJson}
            className="flex w-full cursor-pointer items-center justify-center gap-2 rounded-xl border border-slate-700/80 bg-[#0b111c] px-4 py-2 text-sm font-medium text-slate-200 shadow-[inset_0_1px_0_rgba(255,255,255,0.04)] hover:border-emerald-500/40 hover:bg-slate-800/80 hover:text-white"
          >
            <Download className="h-4 w-4 text-emerald-400" />
            Export Audit JSON
          </button>
        </div>
      </aside>

      {/* Main Content */}
      <div className="flex min-w-0 flex-1 flex-col lg:overflow-y-auto">
        <header className="sticky top-0 z-20 flex min-h-[52px] flex-wrap items-center justify-between gap-x-4 gap-y-2 border-b border-slate-800/80 bg-[#090e17]/90 px-4 py-2 backdrop-blur-xl lg:px-5">
          <div className="flex min-w-0 items-center gap-2.5 text-sm">
            <span className="shrink-0 font-mono text-[11px] uppercase tracking-[0.14em] text-slate-500">
              Proxy Endpoint
            </span>
            <code className="truncate rounded-lg border border-slate-800 bg-[#070b13] px-2.5 py-1 font-mono text-xs text-emerald-300 shadow-[inset_0_1px_2px_rgba(0,0,0,0.4)]">
              POST /v1/chat/completions
            </code>
          </div>

          <div className="flex flex-wrap items-center justify-end gap-2">
            {policy && (
              <>
                <span className="hidden items-center gap-1.5 rounded-lg border border-cyan-500/20 bg-cyan-500/8 px-2.5 py-1 font-mono text-[11px] font-medium text-cyan-300 md:inline-flex">
                  <ShieldCheck className="h-3.5 w-3.5 text-cyan-400" />
                  {policy.failure_mode.toUpperCase()}
                </span>
                <span className="hidden items-center gap-1.5 rounded-lg border border-slate-800 bg-[#070b13] px-2.5 py-1 font-mono text-[11px] text-slate-300 lg:inline-flex">
                  {policy.rate_limit_rpm} RPM · PII/KEY REDACT
                </span>
              </>
            )}

            <div
              className={`flex items-center gap-2 rounded-full border px-3 py-1 text-xs font-semibold ${
                gatewayOnline
                  ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-200"
                  : "border-rose-500/30 bg-rose-500/10 text-rose-200"
              }`}
            >
              <span
                className={`h-2 w-2 rounded-full ${
                  gatewayOnline
                    ? "bg-emerald-400 shadow-[0_0_8px_#10b981] animate-pulse"
                    : "bg-rose-500"
                }`}
              />
              <span>{gatewayOnline ? "Gateway Online" : "Gateway Offline"}</span>
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

        {/* Workspace Body */}
        <main className="w-full flex-1 space-y-3.5 p-4 lg:p-5">
          <div className="grid grid-cols-1 gap-3.5 sm:grid-cols-2 xl:grid-cols-4">
            <div className="attroxx-surface relative overflow-hidden rounded-2xl border border-slate-800/90 px-4 py-3.5">
              <div className="absolute inset-x-0 top-0 h-[2px] bg-gradient-to-r from-emerald-400/90 via-emerald-400/40 to-transparent" />
              <div className="flex items-center justify-between gap-2">
                <span className="font-mono text-[11px] font-semibold uppercase tracking-[0.14em] text-slate-400">
                  Total Inspected
                </span>
                <span className="flex h-7 w-7 items-center justify-center rounded-lg border border-emerald-500/25 bg-emerald-500/10 text-emerald-400">
                  <Activity className="h-3.5 w-3.5" />
                </span>
              </div>
              <div className="mt-2 text-2xl font-semibold tracking-tight text-white tabular-nums xl:text-[1.7rem]">
                {metrics.total}
              </div>
              <div className="mt-1 text-xs text-slate-400">
                Chat &amp; RAG payloads scanned
              </div>
            </div>

            <div className="attroxx-surface relative overflow-hidden rounded-2xl border border-slate-800/90 px-4 py-3.5">
              <div className="absolute inset-x-0 top-0 h-[2px] bg-gradient-to-r from-rose-400/90 via-rose-400/40 to-transparent" />
              <div className="flex items-center justify-between gap-2">
                <span className="font-mono text-[11px] font-semibold uppercase tracking-[0.14em] text-slate-400">
                  Threats Blocked
                </span>
                <span className="inline-flex items-center gap-1 rounded-md border border-rose-500/30 bg-rose-500/12 px-2 py-0.5 font-mono text-[11px] font-semibold text-rose-300 tabular-nums">
                  <ShieldAlert className="h-3 w-3" />
                  {metrics.blockRate}%
                </span>
              </div>
              <div className="mt-2 text-2xl font-semibold tracking-tight text-white tabular-nums xl:text-[1.7rem]">
                {metrics.blocked}
              </div>
              <div className="mt-1 text-xs text-slate-400">
                Zero upstream model leakage
              </div>
            </div>

            <div className="attroxx-surface relative overflow-hidden rounded-2xl border border-slate-800/90 px-4 py-3.5">
              <div className="absolute inset-x-0 top-0 h-[2px] bg-gradient-to-r from-amber-400/90 via-amber-400/40 to-transparent" />
              <div className="flex items-center justify-between gap-2">
                <span className="font-mono text-[11px] font-semibold uppercase tracking-[0.14em] text-slate-400">
                  Mean Latency
                </span>
                <span className="flex h-7 w-7 items-center justify-center rounded-lg border border-amber-500/25 bg-amber-500/10 text-amber-400">
                  <Clock className="h-3.5 w-3.5" />
                </span>
              </div>
              <div className="mt-2 flex items-baseline gap-1.5">
                <span className="text-2xl font-semibold tracking-tight text-white tabular-nums xl:text-[1.7rem]">
                  {metrics.meanLatency}
                </span>
                <span className="font-mono text-xs text-slate-400">ms</span>
              </div>
              <div className="mt-1 text-xs text-slate-400">
                L1 deterministic &lt; 0.2 ms
              </div>
            </div>

            <div className="attroxx-surface relative overflow-hidden rounded-2xl border border-slate-800/90 px-4 py-3.5">
              <div className="absolute inset-x-0 top-0 h-[2px] bg-gradient-to-r from-cyan-400/90 via-cyan-400/40 to-transparent" />
              <div className="flex items-center justify-between gap-2">
                <span className="font-mono text-[11px] font-semibold uppercase tracking-[0.14em] text-slate-400">
                  Egress Canary
                </span>
                <span className="flex h-7 w-7 items-center justify-center rounded-lg border border-cyan-500/25 bg-cyan-500/10 text-cyan-300">
                  <Lock className="h-3.5 w-3.5" />
                </span>
              </div>
              <div className="mt-2 text-2xl font-semibold tracking-tight text-emerald-300 xl:text-[1.7rem]">
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
