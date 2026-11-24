"use client";

import React, { useCallback, useEffect, useMemo, useState } from "react";
import {
  Activity,
  BarChart3,
  Download,
  FileText,
  Shield,
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
        if (logs.length > 0 && !selectedTelemetry) {
          setSelectedTelemetry(logs[0]);
        }
      }
    } catch {
      setGatewayOnline(false);
    }
  }, [selectedTelemetry]);

  useEffect(() => {
    loadInitialState();
    const evtSource = new EventSource(`${API_BASE}/v1/events/stream`);
    evtSource.onmessage = (event) => {
      try {
        const parsed: SecurityTelemetry = JSON.parse(event.data);
        setAuditLogs((prev) => [parsed, ...prev.slice(0, 99)]);
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
    <div className="min-h-screen bg-[#09090b] text-zinc-100 flex">
      {/* Minimal Left Sidebar */}
      <aside className="w-60 border-r border-zinc-800 bg-zinc-950 flex flex-col justify-between shrink-0">
        <div>
          <div className="px-5 py-5 border-b border-zinc-800 flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-zinc-900 border border-zinc-700 flex items-center justify-center">
              <Shield className="w-4 h-4 text-zinc-100" />
            </div>
            <div>
              <div className="text-sm font-semibold tracking-tight text-white">
                ATTROXX
              </div>
              <div className="text-xs text-zinc-500">AI Security Gateway</div>
            </div>
          </div>

          <nav className="p-3 space-y-1">
            <div className="px-2.5 py-1.5 text-[11px] font-medium uppercase tracking-wider text-zinc-500">
              Workspace
            </div>

            <button
              onClick={() => setActiveTab("lab")}
              className={`w-full flex items-center gap-2.5 px-3 py-2 rounded-md text-sm font-medium transition-colors cursor-pointer ${
                activeTab === "lab"
                  ? "bg-zinc-900 text-white border border-zinc-800"
                  : "text-zinc-400 hover:text-zinc-200 hover:bg-zinc-900/50"
              }`}
            >
              <Terminal className="w-4 h-4 text-zinc-400" />
              Inspection Lab
            </button>

            <button
              onClick={() => setActiveTab("analytics")}
              className={`w-full flex items-center gap-2.5 px-3 py-2 rounded-md text-sm font-medium transition-colors cursor-pointer ${
                activeTab === "analytics"
                  ? "bg-zinc-900 text-white border border-zinc-800"
                  : "text-zinc-400 hover:text-zinc-200 hover:bg-zinc-900/50"
              }`}
            >
              <BarChart3 className="w-4 h-4 text-zinc-400" />
              Threat Analytics
            </button>

            <button
              onClick={() => setActiveTab("ledger")}
              className={`w-full flex items-center justify-between px-3 py-2 rounded-md text-sm font-medium transition-colors cursor-pointer ${
                activeTab === "ledger"
                  ? "bg-zinc-900 text-white border border-zinc-800"
                  : "text-zinc-400 hover:text-zinc-200 hover:bg-zinc-900/50"
              }`}
            >
              <span className="flex items-center gap-2.5">
                <FileText className="w-4 h-4 text-zinc-400" />
                Incident Ledger
              </span>
              <span className="text-xs font-mono text-zinc-500">
                {auditLogs.length}
              </span>
            </button>
          </nav>

          {/* Clean Pipeline Status List */}
          <div className="px-5 py-4 mt-2 border-t border-zinc-800/80">
            <div className="text-[11px] font-medium uppercase tracking-wider text-zinc-500 mb-3">
              Active Guards
            </div>
            <div className="space-y-2.5 text-xs">
              {[
                { label: "L0 Normalizer", state: "Ready" },
                { label: "L1 Regex & Entropy", state: "Ready" },
                { label: "L2 Prompt Guard 2", state: "Ready" },
                { label: "L3 Judge & Canary", state: "Armed" },
              ].map((item) => (
                <div key={item.label} className="flex items-center justify-between">
                  <span className="text-zinc-400">{item.label}</span>
                  <span className="font-mono text-zinc-500">{item.state}</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        <div className="p-4 border-t border-zinc-800">
          <button
            onClick={handleExportJson}
            className="w-full flex items-center justify-center gap-2 px-3 py-2 rounded-md text-xs font-medium bg-zinc-900 hover:bg-zinc-800 text-zinc-200 border border-zinc-800 transition-colors cursor-pointer"
          >
            <Download className="w-3.5 h-3.5" />
            Export Audit JSON
          </button>
        </div>
      </aside>

      {/* Main Content */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Top Header */}
        <header className="h-14 px-6 border-b border-zinc-800 bg-zinc-950 flex items-center justify-between">
          <div className="flex items-center gap-3 text-xs">
            <span className="text-zinc-500">Endpoint</span>
            <code className="px-2 py-0.5 rounded bg-zinc-900 border border-zinc-800 text-zinc-300 font-mono">
              POST /v1/chat/completions
            </code>
          </div>

          <div className="flex items-center gap-2 text-xs font-medium px-2.5 py-1 rounded-full bg-zinc-900 border border-zinc-800">
            <span
              className={`w-2 h-2 rounded-full ${
                gatewayOnline ? "bg-emerald-500" : "bg-red-500"
              }`}
            />
            <span className="text-zinc-300">
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

        {/* Workspace Body */}
        <main className="flex-1 p-6 max-w-7xl w-full mx-auto space-y-6">
          {/* 4 Minimal KPI Cards */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <div className="p-4 rounded-lg bg-[#111113] border border-zinc-800">
              <div className="flex items-center justify-between text-xs text-zinc-400">
                <span>Total Inspected</span>
                <Activity className="w-3.5 h-3.5 text-zinc-500" />
              </div>
              <div className="mt-2 text-2xl font-semibold tracking-tight text-white">
                {metrics.total}
              </div>
              <div className="mt-1 text-xs text-zinc-500">
                Chat & RAG requests
              </div>
            </div>

            <div className="p-4 rounded-lg bg-[#111113] border border-zinc-800">
              <div className="flex items-center justify-between text-xs text-zinc-400">
                <span>Threats Blocked</span>
                <span className="text-xs font-mono text-red-400">
                  {metrics.blockRate}%
                </span>
              </div>
              <div className="mt-2 text-2xl font-semibold tracking-tight text-white">
                {metrics.blocked}
              </div>
              <div className="mt-1 text-xs text-zinc-500">
                Zero upstream leakage
              </div>
            </div>

            <div className="p-4 rounded-lg bg-[#111113] border border-zinc-800">
              <div className="flex items-center justify-between text-xs text-zinc-400">
                <span>Mean Latency</span>
                <span className="text-xs font-mono text-zinc-500">AVG</span>
              </div>
              <div className="mt-2 flex items-baseline gap-1.5">
                <span className="text-2xl font-semibold tracking-tight text-white">
                  {metrics.meanLatency}
                </span>
                <span className="text-xs text-zinc-500 font-mono">ms</span>
              </div>
              <div className="mt-1 text-xs text-zinc-500">
                L1 short-circuit &lt; 1ms
              </div>
            </div>

            <div className="p-4 rounded-lg bg-[#111113] border border-zinc-800">
              <div className="flex items-center justify-between text-xs text-zinc-400">
                <span>Egress Canary</span>
                <span className="w-2 h-2 rounded-full bg-emerald-500" />
              </div>
              <div className="mt-2 text-2xl font-semibold tracking-tight text-white">
                Sealed
              </div>
              <div className="mt-1 text-xs text-zinc-500">
                Dynamic session token
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
                setAuditLogs((prev) => [t, ...prev.slice(0, 99)]);
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
