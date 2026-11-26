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
  Terminal,
} from "lucide-react";
import AttackLabTab, { type SecurityTelemetry } from "@/components/AttackLabTab";
import { AuditLogsView, TelemetryView } from "@/components/TelemetryAndLogs";
import LiveTicker from "@/components/LiveTicker";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

export default function Home() {
  const [activeTab, setActiveTab] = useState<"lab" | "analytics" | "ledger">("lab");
  const [gatewayOnline, setGatewayOnline] = useState<boolean>(false);
  const [auditLogs, setAuditLogs] = useState<SecurityTelemetry[]>([]);
  const [selectedTelemetry, setSelectedTelemetry] = useState<SecurityTelemetry | null>(null);

  const loadInitialState = useCallback(async () => {
    try {
      const health = await fetch(`${API_BASE}/health`);
      setGatewayOnline(health.ok);

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
        setAuditLogs((prev) => (parsed.id && prev.some((item) => item.id === parsed.id) ? prev : [parsed, ...prev.slice(0, 99)]));
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
    <div className="min-h-screen bg-[#0b0f19] text-slate-100 flex">
      {/* Sidebar */}
      <aside className="w-64 border-r border-slate-800 bg-[#0d1322] flex flex-col justify-between shrink-0">
        <div>
          {/* Prominent Brand Header */}
          <div className="px-6 py-6 border-b border-slate-800 flex items-center gap-3.5">
            <div className="w-10 h-10 rounded-xl bg-indigo-600/20 border border-indigo-500/40 flex items-center justify-center shadow-sm">
              <Shield className="w-5 h-5 text-indigo-400" />
            </div>
            <div>
              <div className="text-xl font-bold tracking-tight text-white leading-none">
                ATTROXX
              </div>
              <div className="text-xs font-medium text-slate-400 mt-1">
                Runtime AI Firewall
              </div>
            </div>
          </div>

          {/* Primary Navigation */}
          <nav className="p-4 space-y-1.5">
            <div className="px-3 py-1.5 text-xs font-semibold uppercase tracking-wider text-slate-500">
              Console
            </div>

            <button
              onClick={() => setActiveTab("lab")}
              className={`w-full flex items-center gap-3 px-3.5 py-2.5 rounded-lg text-sm font-medium transition-colors cursor-pointer ${
                activeTab === "lab"
                  ? "bg-indigo-600/15 text-white border border-indigo-500/30"
                  : "text-slate-400 hover:text-slate-100 hover:bg-slate-800/60"
              }`}
            >
              <Terminal
                className={`w-4 h-4 ${
                  activeTab === "lab" ? "text-indigo-400" : "text-slate-400"
                }`}
              />
              Inspection Lab
            </button>

            <button
              onClick={() => setActiveTab("analytics")}
              className={`w-full flex items-center gap-3 px-3.5 py-2.5 rounded-lg text-sm font-medium transition-colors cursor-pointer ${
                activeTab === "analytics"
                  ? "bg-indigo-600/15 text-white border border-indigo-500/30"
                  : "text-slate-400 hover:text-slate-100 hover:bg-slate-800/60"
              }`}
            >
              <BarChart3
                className={`w-4 h-4 ${
                  activeTab === "analytics" ? "text-indigo-400" : "text-slate-400"
                }`}
              />
              Threat Analytics
            </button>

            <button
              onClick={() => setActiveTab("ledger")}
              className={`w-full flex items-center justify-between px-3.5 py-2.5 rounded-lg text-sm font-medium transition-colors cursor-pointer ${
                activeTab === "ledger"
                  ? "bg-indigo-600/15 text-white border border-indigo-500/30"
                  : "text-slate-400 hover:text-slate-100 hover:bg-slate-800/60"
              }`}
            >
              <span className="flex items-center gap-3">
                <FileText
                  className={`w-4 h-4 ${
                    activeTab === "ledger" ? "text-indigo-400" : "text-slate-400"
                  }`}
                />
                Incident Ledger
              </span>
              <span className="text-xs font-mono px-2 py-0.5 rounded-full bg-slate-800 text-slate-300">
                {auditLogs.length}
              </span>
            </button>
          </nav>

          {/* Defense Engines */}
          <div className="px-6 py-5 mt-2 border-t border-slate-800/80">
            <div className="text-xs font-semibold uppercase tracking-wider text-slate-500 mb-3.5">
              Defense Layers
            </div>
            <div className="space-y-3 text-sm">
              {[
                { label: "L0 Normalizer", state: "Active", color: "text-emerald-400" },
                { label: "L1 Regex & Entropy", state: "Active", color: "text-emerald-400" },
                { label: "L2 Prompt Guard 2", state: "Active", color: "text-indigo-400" },
                { label: "L3 Judge & Canary", state: "Armed", color: "text-amber-400" },
              ].map((item) => (
                <div key={item.label} className="flex items-center justify-between">
                  <span className="text-slate-300 text-xs">{item.label}</span>
                  <span className={`font-mono text-xs font-medium ${item.color}`}>
                    {item.state}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>

        <div className="p-4 border-t border-slate-800">
          <button
            onClick={handleExportJson}
            className="w-full flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg text-sm font-medium bg-slate-900 hover:bg-slate-800 text-slate-200 border border-slate-700 transition-colors cursor-pointer"
          >
            <Download className="w-4 h-4 text-indigo-400" />
            Export Audit JSON
          </button>
        </div>
      </aside>

      {/* Main Content */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Top Bar */}
        <header className="h-16 px-6 lg:px-8 border-b border-slate-800 bg-[#0d1322] flex items-center justify-between">
          <div className="flex items-center gap-3 text-sm">
            <span className="text-slate-400 font-medium">Proxy Endpoint</span>
            <code className="px-3 py-1 rounded-md bg-slate-900 border border-slate-700/80 text-indigo-300 font-mono text-xs">
              POST /v1/chat/completions
            </code>
          </div>

          <div className="flex items-center gap-2.5 text-xs font-semibold px-3.5 py-1.5 rounded-full bg-slate-900 border border-slate-700/80">
            <span
              className={`w-2.5 h-2.5 rounded-full ${
                gatewayOnline ? "bg-emerald-400" : "bg-rose-500"
              }`}
            />
            <span className="text-slate-200">
              {gatewayOnline ? "Gateway Online" : "Gateway Offline"}
            </span>
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
            <div className="p-5 rounded-xl bg-[#111827] border border-slate-800 border-l-4 border-l-indigo-500">
              <div className="flex items-center justify-between text-sm font-medium text-slate-400">
                <span>Total Inspected</span>
                <Activity className="w-4 h-4 text-indigo-400" />
              </div>
              <div className="mt-2.5 text-3xl font-bold tracking-tight text-white">
                {metrics.total}
              </div>
              <div className="mt-1 text-xs text-slate-400">
                Chat & RAG payloads scanned
              </div>
            </div>

            <div className="p-5 rounded-xl bg-[#111827] border border-slate-800 border-l-4 border-l-rose-500">
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

            <div className="p-5 rounded-xl bg-[#111827] border border-slate-800 border-l-4 border-l-amber-500">
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
                L1 deterministic &lt; 1 ms
              </div>
            </div>

            <div className="p-5 rounded-xl bg-[#111827] border border-slate-800 border-l-4 border-l-emerald-500">
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
                setAuditLogs((prev) => (t.id && prev.some((item) => item.id === t.id) ? prev : [t, ...prev.slice(0, 99)]));
              }}
            />
          )}

          {activeTab === "analytics" && <TelemetryView auditLogs={auditLogs} />}

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
