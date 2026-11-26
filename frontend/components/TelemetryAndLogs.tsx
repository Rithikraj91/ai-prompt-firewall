"use client";

import React, { useMemo, useState } from "react";
import {
  Activity,
  Cpu,
  Gauge,
  Layers,
  Lock,
  Search,
  ShieldAlert,
  ShieldCheck,
  SlidersHorizontal,
  X,
  Zap,
} from "lucide-react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import type { SecurityTelemetry } from "./AttackLabTab";

const BAR_COLORS = [
  "#10b981",
  "#059669",
  "#06b6d4",
  "#0284c7",
  "#14b8a6",
  "#34d399",
];

export function TelemetryView({
  auditLogs,
  apiBase = "http://localhost:8000",
}: {
  auditLogs: SecurityTelemetry[];
  apiBase?: string;
}) {
  const [bench, setBench] = React.useState<any>(null);

  React.useEffect(() => {
    fetch(`${apiBase}/v1/benchmarks`)
      .then((r) => (r.ok ? r.json() : null))
      .then((d) => {
        if (d?.available) setBench(d);
      })
      .catch(() => {});
  }, [apiBase]);
  const [simThreshold, setSimThreshold] = useState<number>(0.82);

  const blockedLogs = useMemo(
    () => auditLogs.filter((l) => l.verdict === "BLOCKED"),
    [auditLogs]
  );

  const taxonomyChartData = useMemo(() => {
    const counts: Record<string, number> = {};
    blockedLogs.forEach((l) => {
      const cat = l.category || "Uncategorized";
      counts[cat] = (counts[cat] || 0) + 1;
    });
    return Object.entries(counts)
      .map(([name, count]) => ({ name, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 6);
  }, [blockedLogs]);

  const layerBreakdown = useMemo(() => {
    const counts: Record<string, number> = {};
    blockedLogs.forEach((l) => {
      const layer = l.blocked_layer || "L1: Regex & Heuristics";
      counts[layer] = (counts[layer] || 0) + 1;
    });

    const getOrder = (name: string) => {
      if (name.startsWith("L0")) return 0;
      if (name.startsWith("L1")) return 1;
      if (name.startsWith("L2")) return 2;
      if (name.startsWith("L3")) return 3;
      return 4;
    };

    const total = blockedLogs.length || 1;
    return Object.entries(counts)
      .map(([layer, count]) => ({
        layer,
        count,
        pct: Math.round((count / total) * 100),
      }))
      .sort((a, b) => getOrder(a.layer) - getOrder(b.layer));
  }, [blockedLogs]);

  const latencyStats = useMemo(() => {
    const fastPathCount = auditLogs.filter((l) => l.total_latency_ms < 5).length;
    const fastPathPct =
      auditLogs.length > 0
        ? Math.round((fastPathCount / auditLogs.length) * 100)
        : 0;
    const avgRisk =
      blockedLogs.length > 0
        ? Math.round(
            (blockedLogs.reduce((acc, l) => acc + l.risk_score, 0) /
              blockedLogs.length) *
              100
          )
        : 0;
    return { fastPathCount, fastPathPct, avgRisk };
  }, [auditLogs, blockedLogs]);

  const simulatedBlocks = useMemo(() => {
    return auditLogs.filter((l) => l.risk_score >= simThreshold).length;
  }, [auditLogs, simThreshold]);

  return (
    <div className="space-y-4">
      {bench && (
        <div className="p-6 rounded-2xl bg-[#0d141b] border border-emerald-500/30 shadow-lg shadow-black/20 space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <div className="text-xs font-mono uppercase tracking-[0.16em] text-emerald-400">
                Reproducible Evaluation Harness
              </div>
              <h3 className="text-base font-semibold text-white mt-0.5">
                ATTROXX Security &amp; Performance Benchmark Suite
              </h3>
            </div>
            <span className="px-3 py-1 rounded-full text-xs font-mono font-semibold bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">
              {bench.security.total_samples} Corpus Vectors · {bench.performance.total_requests} Load Requests
            </span>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
            <div className="p-3.5 rounded-xl bg-[#080c10] border border-slate-800">
              <div className="text-[11px] text-slate-400 uppercase font-semibold">F1-Score</div>
              <div className="text-xl font-mono font-bold text-emerald-400 mt-1">
                {(bench.security.f1_score * 100).toFixed(1)}%
              </div>
              <div className="text-[10px] font-mono text-slate-500 mt-0.5">
                P: {(bench.security.precision * 100).toFixed(0)}% · R: {(bench.security.recall * 100).toFixed(0)}%
              </div>
            </div>

            <div className="p-3.5 rounded-xl bg-[#080c10] border border-slate-800">
              <div className="text-[11px] text-slate-400 uppercase font-semibold">False Positive</div>
              <div className="text-xl font-mono font-bold text-cyan-400 mt-1">
                {(bench.security.false_positive_rate * 100).toFixed(1)}%
              </div>
              <div className="text-[10px] font-mono text-slate-500 mt-0.5">
                {bench.security.true_negatives}/{bench.security.true_negatives + bench.security.false_positives} benign clean
              </div>
            </div>

            <div className="p-3.5 rounded-xl bg-[#080c10] border border-slate-800">
              <div className="text-[11px] text-slate-400 uppercase font-semibold">P50 Latency</div>
              <div className="text-xl font-mono font-bold text-white mt-1">
                {bench.performance.latency_ms.p50} <span className="text-xs font-normal text-slate-400">ms</span>
              </div>
              <div className="text-[10px] font-mono text-slate-500 mt-0.5">Median gateway overhead</div>
            </div>

            <div className="p-3.5 rounded-xl bg-[#080c10] border border-slate-800">
              <div className="text-[11px] text-slate-400 uppercase font-semibold">P95 / P99</div>
              <div className="text-lg font-mono font-bold text-amber-300 mt-1">
                {bench.performance.latency_ms.p95} / {bench.performance.latency_ms.p99}
              </div>
              <div className="text-[10px] font-mono text-slate-500 mt-0.5">Tail latency (ms)</div>
            </div>

            <div className="p-3.5 rounded-xl bg-[#080c10] border border-slate-800">
              <div className="text-[11px] text-slate-400 uppercase font-semibold">Throughput</div>
              <div className="text-xl font-mono font-bold text-emerald-300 mt-1">
                {bench.performance.throughput_rps} <span className="text-xs font-normal text-slate-400">req/s</span>
              </div>
              <div className="text-[10px] font-mono text-slate-500 mt-0.5">Concurrency={bench.performance.concurrency}</div>
            </div>

            <div className="p-3.5 rounded-xl bg-[#080c10] border border-slate-800">
              <div className="text-[11px] text-slate-400 uppercase font-semibold">Peak Memory</div>
              <div className="text-xl font-mono font-bold text-slate-200 mt-1">
                {bench.performance.memory_rss_mb.peak} <span className="text-xs font-normal text-slate-400">MB</span>
              </div>
              <div className="text-[10px] font-mono text-slate-500 mt-0.5">Process RSS footprint</div>
            </div>
          </div>
        </div>
      )}
      {/* Main Analytics Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* Left: Threat Taxonomy Breakdown */}
        <div className="lg:col-span-7 p-6 rounded-2xl bg-[#0d141b] border border-slate-800/90 shadow-lg shadow-black/20 flex flex-col gap-5">
          <div className="flex items-start justify-between gap-4">
            <div>
              <div className="flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-emerald-400" />
                <h2 className="text-base font-semibold text-white tracking-tight">
                  Blocked Threat Taxonomy
                </h2>
              </div>
              <p className="text-xs text-slate-400 mt-1">
                Distribution of intercepted prompt &amp; RAG attack vectors
              </p>
            </div>
            <span className="px-3 py-1 rounded-full text-xs font-mono font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/25">
              {blockedLogs.length} Intercepted
            </span>
          </div>

          {taxonomyChartData.length === 0 ? (
            <div className="flex-1 flex flex-col items-center justify-center text-center border border-dashed border-slate-800 rounded-xl p-8">
              <Activity className="w-6 h-6 text-slate-500 mb-2" />
              <p className="text-sm text-slate-300 font-medium">
                No blocked attacks recorded yet
              </p>
              <p className="text-xs text-slate-500 mt-1">
                Run attack vectors in Inspection Lab to populate threat distribution.
              </p>
            </div>
          ) : (
            <>
              {/* Top Vector Summary Strip */}
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
                <div className="p-3 rounded-xl bg-[#080c10] border border-slate-800/90">
                  <div className="text-[11px] uppercase tracking-wider text-slate-500 font-semibold">
                    Primary Vector
                  </div>
                  <div className="text-xs font-semibold text-emerald-300 mt-1 truncate">
                    {taxonomyChartData[0]?.name}
                  </div>
                </div>
                <div className="p-3 rounded-xl bg-[#080c10] border border-slate-800/90">
                  <div className="text-[11px] uppercase tracking-wider text-slate-500 font-semibold">
                    Active Categories
                  </div>
                  <div className="text-sm font-mono font-bold text-white mt-0.5">
                    {taxonomyChartData.length}{" "}
                    <span className="text-xs font-normal text-slate-400">vectors</span>
                  </div>
                </div>
                <div className="col-span-2 sm:col-span-1 p-3 rounded-xl bg-[#080c10] border border-slate-800/90">
                  <div className="text-[11px] uppercase tracking-wider text-slate-500 font-semibold">
                    Top Share
                  </div>
                  <div className="text-sm font-mono font-bold text-cyan-400 mt-0.5">
                    {Math.round(
                      ((taxonomyChartData[0]?.count || 0) /
                        Math.max(blockedLogs.length, 1)) *
                        100
                    )}
                    %{" "}
                    <span className="text-xs font-normal text-slate-400">
                      of blocks
                    </span>
                  </div>
                </div>
              </div>

              {/* Recharts Horizontal Bar Graph */}
              <div className="flex-1 min-h-[300px] w-full pt-1">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart
                    data={taxonomyChartData}
                    layout="vertical"
                    margin={{ top: 6, right: 32, left: 10, bottom: 6 }}
                  >
                    <defs>
                      <linearGradient id="emeraldBarGrad" x1="0" y1="0" x2="1" y2="0">
                        <stop offset="0%" stopColor="#059669" />
                        <stop offset="100%" stopColor="#10b981" />
                      </linearGradient>
                      <linearGradient id="cyanBarGrad" x1="0" y1="0" x2="1" y2="0">
                        <stop offset="0%" stopColor="#0284c7" />
                        <stop offset="100%" stopColor="#06b6d4" />
                      </linearGradient>
                    </defs>
                    <CartesianGrid
                      stroke="#1e293b"
                      strokeDasharray="3 3"
                      horizontal={false}
                    />
                    <XAxis
                      type="number"
                      stroke="#64748b"
                      fontSize={11}
                      allowDecimals={false}
                      tickLine={false}
                      axisLine={{ stroke: "#1e293b" }}
                    />
                    <YAxis
                      type="category"
                      dataKey="name"
                      stroke="#cbd5e1"
                      fontSize={11}
                      width={185}
                      tickLine={false}
                      axisLine={{ stroke: "#1e293b" }}
                    />
                    <Tooltip
                      cursor={{ fill: "rgba(16, 185, 129, 0.07)" }}
                      contentStyle={{
                        backgroundColor: "#080c10",
                        borderColor: "#1e293b",
                        borderRadius: "10px",
                        fontSize: "12px",
                        color: "#f8fafc",
                      }}
                    />
                    <Bar
                      dataKey="count"
                      radius={[0, 8, 8, 0]}
                      barSize={24}
                      label={{
                        position: "right",
                        fill: "#94a3b8",
                        fontSize: 11,
                        fontFamily: "monospace",
                      }}
                    >
                      {taxonomyChartData.map((_, i) => (
                        <Cell
                          key={i}
                          fill={i % 2 === 0 ? "url(#emeraldBarGrad)" : "url(#cyanBarGrad)"}
                        />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </>
          )}
        </div>

        {/* Right: Enforcement by Layer + Threshold Simulator */}
        <div className="lg:col-span-5 flex flex-col gap-4">
          {/* Enforcement by Layer */}
          <div className="p-6 rounded-2xl bg-[#0d141b] border border-slate-800/90 shadow-lg shadow-black/20 space-y-4">
            <div className="flex items-start justify-between">
              <div>
                <div className="flex items-center gap-2">
                  <Layers className="w-4 h-4 text-emerald-400" />
                  <h2 className="text-base font-semibold text-white tracking-tight">
                    Enforcement by Layer
                  </h2>
                </div>
                <p className="text-xs text-slate-400 mt-1">
                  Pipeline stage where malicious payloads were halted
                </p>
              </div>
              <span className="text-[11px] font-mono text-slate-400">
                L1 → L3
              </span>
            </div>

            {layerBreakdown.length === 0 ? (
              <p className="text-xs text-slate-400 py-4">
                No layer blocks logged yet.
              </p>
            ) : (
              <div className="space-y-3 pt-1">
                {layerBreakdown.map(({ layer, count, pct }) => {
                  const isL1 = layer.startsWith("L1");
                  const isL2 = layer.startsWith("L2");
                  const barColor = isL1
                    ? "bg-emerald-500"
                    : isL2
                    ? "bg-cyan-400"
                    : "bg-amber-400";
                  const badgeColor = isL1
                    ? "text-emerald-400 bg-emerald-500/10 border-emerald-500/20"
                    : isL2
                    ? "text-cyan-400 bg-cyan-500/10 border-cyan-500/20"
                    : "text-amber-400 bg-amber-500/10 border-amber-500/20";

                  return (
                    <div
                      key={layer}
                      className="p-3.5 rounded-xl bg-[#080c10] border border-slate-800/90 space-y-2"
                    >
                      <div className="flex items-center justify-between text-xs">
                        <span className="text-slate-200 font-medium">
                          {layer}
                        </span>
                        <div className="flex items-center gap-2">
                          <span
                            className={`px-2 py-0.5 rounded font-mono text-[11px] border ${badgeColor}`}
                          >
                            {pct}%
                          </span>
                          <span className="font-mono text-rose-400 font-semibold">
                            {count} blocked
                          </span>
                        </div>
                      </div>
                      <div className="w-full h-1.5 rounded-full bg-slate-800/90 overflow-hidden">
                        <div
                          className={`h-full rounded-full ${barColor} transition-all duration-500`}
                          style={{ width: `${Math.max(pct, 6)}%` }}
                        />
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          {/* Threshold Simulator */}
          <div className="p-6 rounded-2xl bg-[#0d141b] border border-slate-800/90 shadow-lg shadow-black/20 space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <div className="flex items-center gap-2">
                  <SlidersHorizontal className="w-4 h-4 text-emerald-400" />
                  <h2 className="text-base font-semibold text-white tracking-tight">
                    Threshold Simulator
                  </h2>
                </div>
                <p className="text-xs text-slate-400 mt-1">
                  Test L2/L3 risk sensitivity on historical traffic
                </p>
              </div>
              <span className="text-sm font-mono font-bold px-3 py-1 rounded-lg bg-[#080c10] border border-emerald-500/30 text-emerald-400">
                {simThreshold.toFixed(2)}
              </span>
            </div>

            <input
              type="range"
              min={0.1}
              max={0.99}
              step={0.01}
              value={simThreshold}
              onChange={(e) => setSimThreshold(parseFloat(e.target.value))}
              className="w-full accent-emerald-500 cursor-pointer"
            />

            <div className="flex items-center justify-between gap-2">
              {[
                { label: "Strict (0.65)", val: 0.65 },
                { label: "Default (0.82)", val: 0.82 },
                { label: "Permissive (0.90)", val: 0.9 },
              ].map((preset) => (
                <button
                  key={preset.label}
                  onClick={() => setSimThreshold(preset.val)}
                  className={`flex-1 py-1.5 px-2 rounded-lg text-[11px] font-mono border cursor-pointer ${
                    Math.abs(simThreshold - preset.val) < 0.005
                      ? "bg-emerald-500/15 border-emerald-500/50 text-emerald-300"
                      : "bg-[#080c10] border-slate-800 text-slate-400 hover:text-slate-200"
                  }`}
                >
                  {preset.label}
                </button>
              ))}
            </div>

            <div className="flex items-center justify-between text-xs text-slate-300 pt-2 border-t border-slate-800/80">
              <span>Projected blocks at threshold:</span>
              <span className="font-mono font-semibold text-white">
                {simulatedBlocks} / {auditLogs.length} requests
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Bottom Security Posture & OWASP Coverage Strip */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
        <div className="p-5 rounded-2xl bg-[#0d141b] border border-slate-800/90 flex items-start gap-3.5">
          <div className="p-2.5 rounded-xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-400">
            <Zap className="w-5 h-5" />
          </div>
          <div className="space-y-1">
            <div className="text-xs font-semibold uppercase tracking-wider text-slate-400">
              Fast-Path Efficiency
            </div>
            <div className="text-lg font-bold text-white font-mono">
              {latencyStats.fastPathPct}%{" "}
              <span className="text-xs font-normal text-slate-400">
                ({latencyStats.fastPathCount} reqs &lt; 5 ms)
              </span>
            </div>
            <p className="text-xs text-slate-400">
              Resolved deterministically at L0/L1 or SHA-256 verdict cache without LLM overhead.
            </p>
          </div>
        </div>

        <div className="p-5 rounded-2xl bg-[#0d141b] border border-slate-800/90 flex items-start gap-3.5">
          <div className="p-2.5 rounded-xl bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">
            <Gauge className="w-5 h-5" />
          </div>
          <div className="space-y-1">
            <div className="text-xs font-semibold uppercase tracking-wider text-slate-400">
              Mean Blocked Confidence
            </div>
            <div className="text-lg font-bold text-white font-mono">
              {latencyStats.avgRisk}%{" "}
              <span className="text-xs font-normal text-slate-400">
                threat certainty
              </span>
            </div>
            <p className="text-xs text-slate-400">
              Combined deterministic signature &amp; Llama Prompt Guard 2 risk score across blocked events.
            </p>
          </div>
        </div>

        <div className="p-5 rounded-2xl bg-[#0d141b] border border-slate-800/90 flex items-start gap-3.5">
          <div className="p-2.5 rounded-xl bg-amber-500/10 border border-amber-500/20 text-amber-400">
            <Lock className="w-5 h-5" />
          </div>
          <div className="space-y-1">
            <div className="text-xs font-semibold uppercase tracking-wider text-slate-400">
              OWASP LLM Top 10 Posture
            </div>
            <div className="flex flex-wrap gap-1.5 pt-0.5">
              <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-emerald-500/10 text-emerald-300 border border-emerald-500/20">
                LLM01 Injection
              </span>
              <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-emerald-500/10 text-emerald-300 border border-emerald-500/20">
                LLM02 Data Leak
              </span>
              <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-emerald-500/10 text-emerald-300 border border-emerald-500/20">
                LLM08 Canary Guard
              </span>
            </div>
            <p className="text-xs text-slate-400 pt-0.5">
              Active ingress normalization, RAG scanning &amp; egress leak checks.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

export function AuditLogsView({
  auditLogs,
  onSelectLog,
}: {
  auditLogs: SecurityTelemetry[];
  onSelectLog?: (ev: SecurityTelemetry) => void;
}) {
  const [query, setQuery] = useState<string>("");
  const [filter, setFilter] = useState<"ALL" | "BLOCKED" | "ALLOWED">("ALL");
  const [drawerLog, setDrawerLog] = useState<SecurityTelemetry | null>(null);

  const filteredLogs = useMemo(() => {
    return auditLogs.filter((l) => {
      if (filter !== "ALL" && l.verdict !== filter) return false;
      if (!query.trim()) return true;
      const q = query.toLowerCase();
      return (
        (l.raw_prompt || "").toLowerCase().includes(q) ||
        (l.category || "").toLowerCase().includes(q) ||
        (l.blocked_layer || "").toLowerCase().includes(q)
      );
    });
  }, [auditLogs, filter, query]);

  return (
    <div className="p-6 rounded-2xl bg-[#0d141b] border border-slate-800/90 shadow-lg shadow-black/20 space-y-5">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h2 className="text-lg font-semibold text-white">Incident Ledger</h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Click any row to inspect full stage telemetry and replay in Inspection Lab
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          <div className="relative">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Filter payloads or layers..."
              className="pl-9 pr-3 py-2 rounded-lg bg-[#080c10] border border-slate-800/80 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-emerald-500"
            />
          </div>

          {(["ALL", "BLOCKED", "ALLOWED"] as const).map((status) => (
            <button
              key={status}
              onClick={() => setFilter(status)}
              className={`px-3 py-2 rounded-lg text-xs font-semibold border transition-colors cursor-pointer ${
                filter === status
                  ? "bg-emerald-600/20 border-emerald-500 text-white"
                  : "bg-[#080c10] border-slate-800/80 text-slate-400 hover:text-slate-200"
              }`}
            >
              {status}
            </button>
          ))}
        </div>
      </div>

      <div className="overflow-x-auto border border-slate-800 rounded-xl">
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="border-b border-slate-800 bg-[#080c10] text-xs font-semibold uppercase tracking-wider text-slate-400">
              <th className="py-3 px-4">Verdict</th>
              <th className="py-3 px-4">Category</th>
              <th className="py-3 px-4">Stage</th>
              <th className="py-3 px-4">Payload Preview</th>
              <th className="py-3 px-4">Risk</th>
              <th className="py-3 px-4 text-right">Latency</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/80 text-sm">
            {filteredLogs.length === 0 ? (
              <tr>
                <td colSpan={6} className="py-10 text-center text-slate-400">
                  No matching audit records found.
                </td>
              </tr>
            ) : (
              filteredLogs.map((log, idx) => {
                const blocked = log.verdict === "BLOCKED";
                return (
                  <tr
                    key={log.id ?? idx}
                    onClick={() => setDrawerLog(log)}
                    className="hover:bg-slate-800/40 transition-colors cursor-pointer"
                  >
                    <td className="py-3 px-4 whitespace-nowrap">
                      <span
                        className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-semibold ${
                          blocked
                            ? "bg-rose-500/15 text-rose-400 border border-rose-500/20"
                            : "bg-emerald-500/15 text-emerald-400 border border-emerald-500/20"
                        }`}
                      >
                        {blocked ? (
                          <ShieldAlert className="w-3.5 h-3.5" />
                        ) : (
                          <ShieldCheck className="w-3.5 h-3.5" />
                        )}
                        {log.verdict}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-slate-200 font-medium whitespace-nowrap">
                      {log.category || "Benign"}
                    </td>
                    <td className="py-3 px-4 font-mono text-xs text-slate-400 whitespace-nowrap">
                      {log.blocked_layer || "All Passed"}
                    </td>
                    <td className="py-3 px-4 font-mono text-xs text-slate-400 max-w-md truncate">
                      {log.raw_prompt}
                    </td>
                    <td className="py-3 px-4 font-mono text-xs text-slate-300">
                      {Math.round(log.risk_score * 100)}%
                    </td>
                    <td className="py-3 px-4 font-mono text-xs text-slate-400 text-right whitespace-nowrap">
                      {log.total_latency_ms.toFixed(1)} ms
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      {drawerLog && (
        <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="max-w-xl w-full rounded-2xl bg-[#0d141b] border border-slate-800 p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Cpu className="w-4 h-4 text-emerald-400" />
                <span className="text-base font-semibold text-white">
                  Event #{drawerLog.id ?? "Trace"}
                </span>
                <span className="text-xs font-mono text-emerald-400">
                  · {drawerLog.category}
                </span>
              </div>
              <button
                onClick={() => setDrawerLog(null)}
                className="p-1.5 rounded-lg hover:bg-slate-800 text-slate-400 cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="grid grid-cols-3 gap-2.5 text-xs">
              <div className="p-2.5 rounded-lg bg-[#080c10] border border-slate-800">
                <div className="text-slate-400">Verdict</div>
                <div
                  className={`font-mono font-semibold mt-0.5 ${
                    drawerLog.verdict === "BLOCKED"
                      ? "text-rose-400"
                      : "text-emerald-400"
                  }`}
                >
                  {drawerLog.verdict}
                </div>
              </div>
              <div className="p-2.5 rounded-lg bg-[#080c10] border border-slate-800">
                <div className="text-slate-400">Risk Score</div>
                <div className="font-mono font-semibold text-white mt-0.5">
                  {Math.round(drawerLog.risk_score * 100)}%
                </div>
              </div>
              <div className="p-2.5 rounded-lg bg-[#080c10] border border-slate-800">
                <div className="text-slate-400">Latency</div>
                <div className="font-mono font-semibold text-cyan-400 mt-0.5">
                  {drawerLog.total_latency_ms.toFixed(1)} ms
                </div>
              </div>
            </div>

            <div className="space-y-2">
              <div className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                Raw Input
              </div>
              <pre className="p-4 rounded-lg bg-[#080c10] border border-slate-800 text-xs font-mono text-slate-200 whitespace-pre-wrap max-h-48 overflow-y-auto">
                {drawerLog.raw_prompt}
              </pre>
            </div>

            <div className="flex justify-end gap-2.5 pt-2">
              {onSelectLog && (
                <button
                  onClick={() => {
                    onSelectLog(drawerLog);
                    setDrawerLog(null);
                  }}
                  className="px-4 py-2 rounded-lg text-xs font-semibold bg-emerald-600 text-white hover:bg-emerald-500 cursor-pointer"
                >
                  Open in Inspection Lab
                </button>
              )}
              <button
                onClick={() => setDrawerLog(null)}
                className="px-4 py-2 rounded-lg text-xs font-medium bg-slate-800 border border-slate-700 text-slate-200 cursor-pointer"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
