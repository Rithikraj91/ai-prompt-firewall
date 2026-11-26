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

export function TelemetryView({
  auditLogs,
  apiBase = "http://localhost:8000",
}: {
  auditLogs: SecurityTelemetry[];
  apiBase?: string;
}) {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
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
    <div className="space-y-3.5">
      {bench && (
        <div className="attroxx-surface relative overflow-hidden space-y-4 rounded-2xl border border-emerald-400/30 p-4 sm:p-5">
          <div className="absolute inset-x-0 top-0 h-[2px] bg-gradient-to-r from-emerald-400 via-cyan-400 to-transparent" />
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <div className="font-mono text-[11px] font-semibold uppercase tracking-[0.18em] text-emerald-400">
                Reproducible Evaluation Harness
              </div>
              <h3 className="mt-0.5 text-base font-semibold tracking-tight text-white">
                ATTROXX Security &amp; Performance Benchmark Suite
              </h3>
            </div>
            <span className="rounded-lg border border-emerald-500/30 bg-emerald-500/12 px-3 py-1 font-mono text-xs font-semibold text-emerald-300 tabular-nums">
              {bench.security.total_samples} Corpus Vectors · {bench.performance.total_requests} Load Requests
            </span>
          </div>

          <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
            <div className="attroxx-well rounded-xl border border-slate-800/90 p-3.5">
              <div className="font-mono text-[10px] font-semibold uppercase tracking-wider text-slate-400">
                F1-Score
              </div>
              <div className="mt-1 font-mono text-xl font-bold text-emerald-400 tabular-nums">
                {(bench.security.f1_score * 100).toFixed(1)}%
              </div>
              <div className="mt-0.5 font-mono text-[10px] text-slate-500 tabular-nums">
                P: {(bench.security.precision * 100).toFixed(0)}% · R: {(bench.security.recall * 100).toFixed(0)}%
              </div>
            </div>

            <div className="attroxx-well rounded-xl border border-slate-800/90 p-3.5">
              <div className="font-mono text-[10px] font-semibold uppercase tracking-wider text-slate-400">
                False Positive
              </div>
              <div className="mt-1 font-mono text-xl font-bold text-cyan-400 tabular-nums">
                {(bench.security.false_positive_rate * 100).toFixed(1)}%
              </div>
              <div className="mt-0.5 font-mono text-[10px] text-slate-500 tabular-nums">
                {bench.security.true_negatives}/{bench.security.true_negatives + bench.security.false_positives} benign clean
              </div>
            </div>

            <div className="attroxx-well rounded-xl border border-slate-800/90 p-3.5">
              <div className="font-mono text-[10px] font-semibold uppercase tracking-wider text-slate-400">
                P50 Latency
              </div>
              <div className="mt-1 font-mono text-xl font-bold text-white tabular-nums">
                {bench.performance.latency_ms.p50}{" "}
                <span className="text-xs font-normal text-slate-400">ms</span>
              </div>
              <div className="mt-0.5 font-mono text-[10px] text-slate-500">
                Median gateway overhead
              </div>
            </div>

            <div className="attroxx-well rounded-xl border border-slate-800/90 p-3.5">
              <div className="font-mono text-[10px] font-semibold uppercase tracking-wider text-slate-400">
                P95 / P99
              </div>
              <div className="mt-1 font-mono text-lg font-bold text-amber-300 tabular-nums">
                {bench.performance.latency_ms.p95} / {bench.performance.latency_ms.p99}
              </div>
              <div className="mt-0.5 font-mono text-[10px] text-slate-500">
                Tail latency (ms)
              </div>
            </div>

            <div className="attroxx-well rounded-xl border border-slate-800/90 p-3.5">
              <div className="font-mono text-[10px] font-semibold uppercase tracking-wider text-slate-400">
                Throughput
              </div>
              <div className="mt-1 font-mono text-xl font-bold text-emerald-300 tabular-nums">
                {bench.performance.throughput_rps}{" "}
                <span className="text-xs font-normal text-slate-400">req/s</span>
              </div>
              <div className="mt-0.5 font-mono text-[10px] text-slate-500 tabular-nums">
                Concurrency={bench.performance.concurrency}
              </div>
            </div>

            <div className="attroxx-well rounded-xl border border-slate-800/90 p-3.5">
              <div className="font-mono text-[10px] font-semibold uppercase tracking-wider text-slate-400">
                Peak Memory
              </div>
              <div className="mt-1 font-mono text-xl font-bold text-slate-200 tabular-nums">
                {bench.performance.memory_rss_mb.peak}{" "}
                <span className="text-xs font-normal text-slate-400">MB</span>
              </div>
              <div className="mt-0.5 font-mono text-[10px] text-slate-500">
                Process RSS footprint
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Main Analytics Grid */}
      <div className="grid grid-cols-1 gap-3.5 lg:grid-cols-12">
        {/* Left: Threat Taxonomy Breakdown */}
        <div className="attroxx-surface flex min-w-0 flex-col gap-4 rounded-2xl border border-slate-800/90 p-4 sm:p-5 lg:col-span-7">
          <div className="flex items-start justify-between gap-4">
            <div>
              <div className="flex items-center gap-2">
                <span className="flex h-7 w-7 items-center justify-center rounded-lg border border-emerald-500/25 bg-emerald-500/10 text-emerald-400">
                  <ShieldAlert className="h-4 w-4" />
                </span>
                <h2 className="text-base font-semibold tracking-tight text-white">
                  Blocked Threat Taxonomy
                </h2>
              </div>
              <p className="mt-1 text-xs text-slate-400">
                Distribution of intercepted prompt &amp; RAG attack vectors
              </p>
            </div>
            <span className="rounded-lg border border-emerald-500/25 bg-emerald-500/10 px-3 py-1 font-mono text-xs font-semibold text-emerald-300 tabular-nums">
              {blockedLogs.length} Intercepted
            </span>
          </div>

          {taxonomyChartData.length === 0 ? (
            <div className="attroxx-well flex flex-1 flex-col items-center justify-center rounded-xl border border-dashed border-slate-800 p-8 text-center">
              <Activity className="mb-2 h-6 w-6 text-slate-500" />
              <p className="text-sm font-medium text-slate-300">
                No blocked attacks recorded yet
              </p>
              <p className="mt-1 text-xs text-slate-500">
                Run attack vectors in Inspection Lab to populate threat distribution.
              </p>
            </div>
          ) : (
            <>
              {/* Top Vector Summary Strip */}
              <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
                <div className="attroxx-well rounded-xl border border-slate-800/90 p-3">
                  <div className="font-mono text-[10px] font-semibold uppercase tracking-wider text-slate-500">
                    Primary Vector
                  </div>
                  <div className="mt-1 truncate text-xs font-semibold text-emerald-300">
                    {taxonomyChartData[0]?.name}
                  </div>
                </div>
                <div className="attroxx-well rounded-xl border border-slate-800/90 p-3">
                  <div className="font-mono text-[10px] font-semibold uppercase tracking-wider text-slate-500">
                    Active Categories
                  </div>
                  <div className="mt-0.5 font-mono text-sm font-bold text-white tabular-nums">
                    {taxonomyChartData.length}{" "}
                    <span className="text-xs font-normal text-slate-400">vectors</span>
                  </div>
                </div>
                <div className="attroxx-well col-span-2 rounded-xl border border-slate-800/90 p-3 sm:col-span-1">
                  <div className="font-mono text-[10px] font-semibold uppercase tracking-wider text-slate-500">
                    Top Share
                  </div>
                  <div className="mt-0.5 font-mono text-sm font-bold text-cyan-400 tabular-nums">
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
              <div className="attroxx-well w-full overflow-x-auto rounded-xl border border-slate-800/80 p-3">
                <div className="h-[300px] min-w-[420px]">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart
                      data={taxonomyChartData}
                      layout="vertical"
                      margin={{ top: 8, right: 36, left: 10, bottom: 8 }}
                    >
                      <defs>
                        <linearGradient id="emeraldBarGrad" x1="0" y1="0" x2="1" y2="0">
                          <stop offset="0%" stopColor="#059669" />
                          <stop offset="100%" stopColor="#34d399" />
                        </linearGradient>
                        <linearGradient id="cyanBarGrad" x1="0" y1="0" x2="1" y2="0">
                          <stop offset="0%" stopColor="#0284c7" />
                          <stop offset="100%" stopColor="#22d3ee" />
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
                        width={148}
                        tickLine={false}
                        axisLine={{ stroke: "#1e293b" }}
                      />
                      <Tooltip
                        cursor={{ fill: "rgba(16, 185, 129, 0.08)" }}
                        contentStyle={{
                          backgroundColor: "#070b13",
                          borderColor: "rgba(52, 211, 153, 0.28)",
                          borderRadius: "10px",
                          fontSize: "12px",
                          color: "#f8fafc",
                          boxShadow: "0 12px 28px rgba(0, 0, 0, 0.55)",
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
              </div>
            </>
          )}
        </div>

        {/* Right: Enforcement by Layer + Threshold Simulator */}
        <div className="flex min-w-0 flex-col gap-3.5 lg:col-span-5">
          {/* Enforcement by Layer */}
          <div className="attroxx-surface space-y-4 rounded-2xl border border-slate-800/90 p-4 sm:p-5">
            <div className="flex items-start justify-between">
              <div>
                <div className="flex items-center gap-2">
                  <span className="flex h-7 w-7 items-center justify-center rounded-lg border border-emerald-500/25 bg-emerald-500/10 text-emerald-400">
                    <Layers className="h-4 w-4" />
                  </span>
                  <h2 className="text-base font-semibold tracking-tight text-white">
                    Enforcement by Layer
                  </h2>
                </div>
                <p className="mt-1 text-xs text-slate-400">
                  Pipeline stage where malicious payloads were halted
                </p>
              </div>
              <span className="rounded-md border border-slate-800 bg-[#070b13] px-2 py-0.5 font-mono text-[11px] text-slate-400">
                L1 → L3
              </span>
            </div>

            {layerBreakdown.length === 0 ? (
              <p className="py-4 text-xs text-slate-400">
                No layer blocks logged yet.
              </p>
            ) : (
              <div className="space-y-2.5 pt-1">
                {layerBreakdown.map(({ layer, count, pct }) => {
                  const isL1 = layer.startsWith("L1");
                  const isL2 = layer.startsWith("L2");
                  const barColor = isL1
                    ? "bg-emerald-500"
                    : isL2
                    ? "bg-cyan-400"
                    : "bg-amber-400";
                  const badgeColor = isL1
                    ? "text-emerald-300 bg-emerald-500/10 border-emerald-500/25"
                    : isL2
                    ? "text-cyan-300 bg-cyan-500/10 border-cyan-500/25"
                    : "text-amber-300 bg-amber-500/10 border-amber-500/25";

                  return (
                    <div
                      key={layer}
                      className="attroxx-well space-y-2 rounded-xl border border-slate-800/90 p-3.5"
                    >
                      <div className="flex items-center justify-between text-xs">
                        <span className="font-medium text-slate-200">
                          {layer}
                        </span>
                        <div className="flex items-center gap-2">
                          <span
                            className={`rounded border px-2 py-0.5 font-mono text-[11px] tabular-nums ${badgeColor}`}
                          >
                            {pct}%
                          </span>
                          <span className="font-mono font-semibold text-rose-400 tabular-nums">
                            {count} blocked
                          </span>
                        </div>
                      </div>
                      <div className="h-1.5 w-full overflow-hidden rounded-full bg-slate-800/90">
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
          <div className="attroxx-surface space-y-4 rounded-2xl border border-slate-800/90 p-4 sm:p-5">
            <div className="flex items-center justify-between gap-2">
              <div>
                <div className="flex items-center gap-2">
                  <span className="flex h-7 w-7 items-center justify-center rounded-lg border border-emerald-500/25 bg-emerald-500/10 text-emerald-400">
                    <SlidersHorizontal className="h-4 w-4" />
                  </span>
                  <h2 className="text-base font-semibold tracking-tight text-white">
                    Threshold Simulator
                  </h2>
                </div>
                <p className="mt-1 text-xs text-slate-400">
                  Test L2/L3 risk sensitivity on historical traffic
                </p>
              </div>
              <span className="rounded-lg border border-emerald-500/35 bg-[#070b13] px-3 py-1 font-mono text-sm font-bold text-emerald-300 tabular-nums">
                {simThreshold.toFixed(2)}
              </span>
            </div>

            <div className="attroxx-well rounded-xl border border-slate-800/90 px-3.5 py-3">
              <input
                type="range"
                min={0.1}
                max={0.99}
                step={0.01}
                value={simThreshold}
                onChange={(e) => setSimThreshold(parseFloat(e.target.value))}
                className="w-full cursor-pointer accent-emerald-500"
              />
              <div className="mt-1 flex justify-between font-mono text-[10px] text-slate-500">
                <span>0.10</span>
                <span>0.50</span>
                <span>0.99</span>
              </div>
            </div>

            <div className="flex items-center justify-between gap-2">
              {[
                { label: "Strict (0.65)", val: 0.65 },
                { label: "Default (0.82)", val: 0.82 },
                { label: "Permissive (0.90)", val: 0.9 },
              ].map((preset) => (
                <button
                  key={preset.label}
                  onClick={() => setSimThreshold(preset.val)}
                  className={`flex-1 cursor-pointer rounded-lg border px-2 py-1.5 font-mono text-[11px] ${
                    Math.abs(simThreshold - preset.val) < 0.005
                      ? "border-emerald-400/50 bg-emerald-500/15 text-emerald-200 shadow-[0_0_14px_rgba(16,185,129,0.12)]"
                      : "border-slate-800 bg-[#070b13] text-slate-400 hover:border-slate-700 hover:text-slate-200"
                  }`}
                >
                  {preset.label}
                </button>
              ))}
            </div>

            <div className="flex items-center justify-between border-t border-slate-800/80 pt-3 text-xs text-slate-300">
              <span>Projected blocks at threshold:</span>
              <span className="font-mono font-semibold text-white tabular-nums">
                {simulatedBlocks} / {auditLogs.length} requests
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Bottom Security Posture & OWASP Coverage Strip */}
      <div className="grid grid-cols-1 gap-3.5 md:grid-cols-3">
        <div className="attroxx-surface flex items-start gap-3.5 rounded-2xl border border-slate-800/90 p-4 sm:p-5">
          <div className="rounded-xl border border-emerald-500/25 bg-emerald-500/10 p-2.5 text-emerald-400">
            <Zap className="h-5 w-5" />
          </div>
          <div className="space-y-1">
            <div className="font-mono text-[11px] font-semibold uppercase tracking-wider text-slate-400">
              Fast-Path Efficiency
            </div>
            <div className="font-mono text-lg font-bold text-white tabular-nums">
              {latencyStats.fastPathPct}%{" "}
              <span className="text-xs font-normal text-slate-400">
                ({latencyStats.fastPathCount} reqs &lt; 5 ms)
              </span>
            </div>
            <p className="text-xs leading-relaxed text-slate-400">
              Resolved deterministically at L0/L1 or SHA-256 verdict cache without LLM overhead.
            </p>
          </div>
        </div>

        <div className="attroxx-surface flex items-start gap-3.5 rounded-2xl border border-slate-800/90 p-4 sm:p-5">
          <div className="rounded-xl border border-cyan-500/25 bg-cyan-500/10 p-2.5 text-cyan-400">
            <Gauge className="h-5 w-5" />
          </div>
          <div className="space-y-1">
            <div className="font-mono text-[11px] font-semibold uppercase tracking-wider text-slate-400">
              Mean Blocked Confidence
            </div>
            <div className="font-mono text-lg font-bold text-white tabular-nums">
              {latencyStats.avgRisk}%{" "}
              <span className="text-xs font-normal text-slate-400">
                threat certainty
              </span>
            </div>
            <p className="text-xs leading-relaxed text-slate-400">
              Combined deterministic signature &amp; Llama Prompt Guard 2 risk score across blocked events.
            </p>
          </div>
        </div>

        <div className="attroxx-surface flex items-start gap-3.5 rounded-2xl border border-slate-800/90 p-4 sm:p-5">
          <div className="rounded-xl border border-amber-500/25 bg-amber-500/10 p-2.5 text-amber-400">
            <Lock className="h-5 w-5" />
          </div>
          <div className="space-y-1">
            <div className="font-mono text-[11px] font-semibold uppercase tracking-wider text-slate-400">
              OWASP LLM Top 10 Posture
            </div>
            <div className="flex flex-wrap gap-1.5 pt-0.5">
              <span className="rounded border border-emerald-500/25 bg-emerald-500/10 px-2 py-0.5 font-mono text-[11px] text-emerald-300">
                LLM01 Injection
              </span>
              <span className="rounded border border-emerald-500/25 bg-emerald-500/10 px-2 py-0.5 font-mono text-[11px] text-emerald-300">
                LLM02 Data Leak
              </span>
              <span className="rounded border border-emerald-500/25 bg-emerald-500/10 px-2 py-0.5 font-mono text-[11px] text-emerald-300">
                LLM08 Canary Guard
              </span>
            </div>
            <p className="pt-0.5 text-xs leading-relaxed text-slate-400">
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
    <div className="attroxx-surface space-y-4 rounded-2xl border border-slate-800/90 p-4 sm:p-5">
      <div className="flex flex-col justify-between gap-3 sm:flex-row sm:items-center">
        <div>
          <div className="flex items-center gap-2">
            <span className="h-2 w-2 rounded-full bg-emerald-400 shadow-[0_0_8px_#10b981]" />
            <h2 className="text-lg font-semibold tracking-tight text-white">
              Incident Ledger
            </h2>
          </div>
          <p className="mt-0.5 text-xs text-slate-400">
            Click any row to inspect full stage telemetry and replay in Inspection Lab
          </p>
        </div>

        <div className="flex w-full flex-wrap items-center gap-2 sm:w-auto">
          <div className="relative min-w-0 flex-1 sm:w-64 sm:flex-none">
            <Search className="absolute top-1/2 left-3 h-4 w-4 -translate-y-1/2 text-slate-500" />
            <input
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Filter payloads or layers..."
              className="attroxx-well w-full rounded-lg border border-slate-800/90 py-2 pr-3 pl-9 text-sm text-slate-200 placeholder:text-slate-500 focus:border-emerald-400/70 focus:outline-none"
            />
          </div>

          <div className="flex items-center gap-1 rounded-lg border border-slate-800/90 bg-[#070b13] p-1">
            {(["ALL", "BLOCKED", "ALLOWED"] as const).map((status) => (
              <button
                key={status}
                onClick={() => setFilter(status)}
                className={`cursor-pointer rounded-md px-3 py-1.5 font-mono text-[11px] font-semibold transition-colors ${
                  filter === status
                    ? "bg-emerald-500/20 text-emerald-200 border border-emerald-500/40"
                    : "border border-transparent text-slate-400 hover:text-slate-200"
                }`}
              >
                {status}
              </button>
            ))}
          </div>
        </div>
      </div>

      <div className="attroxx-well overflow-x-auto rounded-xl border border-slate-800/90">
        <table className="w-full min-w-[760px] border-collapse text-left">
          <thead>
            <tr className="border-b border-slate-800/90 bg-[#090f19] font-mono text-[11px] font-semibold uppercase tracking-wider text-slate-400">
              <th className="px-4 py-3">Verdict</th>
              <th className="px-4 py-3">Category</th>
              <th className="px-4 py-3">Stage</th>
              <th className="px-4 py-3">Payload Preview</th>
              <th className="px-4 py-3">Risk</th>
              <th className="px-4 py-3 text-right">Latency</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/70 text-sm">
            {filteredLogs.length === 0 ? (
              <tr>
                <td colSpan={6} className="py-12 text-center text-slate-400">
                  No matching audit records found.
                </td>
              </tr>
            ) : (
              filteredLogs.map((log, idx) => {
                const blocked = log.verdict === "BLOCKED";
                const riskPct = Math.round(log.risk_score * 100);
                return (
                  <tr
                    key={log.id ?? idx}
                    onClick={() => setDrawerLog(log)}
                    className="cursor-pointer transition-colors hover:bg-emerald-400/[0.045]"
                  >
                    <td className="whitespace-nowrap px-4 py-3">
                      <span
                        className={`inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1 font-mono text-[11px] font-semibold ${
                          blocked
                            ? "border-rose-500/25 bg-rose-500/12 text-rose-300"
                            : "border-emerald-500/25 bg-emerald-500/12 text-emerald-300"
                        }`}
                      >
                        {blocked ? (
                          <ShieldAlert className="h-3.5 w-3.5" />
                        ) : (
                          <ShieldCheck className="h-3.5 w-3.5" />
                        )}
                        {log.verdict}
                      </span>
                    </td>
                    <td className="whitespace-nowrap px-4 py-3 font-medium text-slate-200">
                      {log.category || "Benign"}
                    </td>
                    <td className="whitespace-nowrap px-4 py-3 font-mono text-xs text-slate-400">
                      {log.blocked_layer || "All Passed"}
                    </td>
                    <td className="max-w-md truncate px-4 py-3 font-mono text-xs text-slate-400">
                      {log.raw_prompt}
                    </td>
                    <td
                      className={`px-4 py-3 font-mono text-xs font-semibold tabular-nums ${
                        riskPct >= 80
                          ? "text-rose-300"
                          : riskPct >= 40
                          ? "text-amber-300"
                          : "text-emerald-300"
                      }`}
                    >
                      {riskPct}%
                    </td>
                    <td className="whitespace-nowrap px-4 py-3 text-right font-mono text-xs text-slate-400 tabular-nums">
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
        <div className="fixed inset-0 z-50 flex items-end justify-center bg-black/75 p-3 backdrop-blur-sm sm:items-center sm:p-4">
          <div className="attroxx-surface relative max-h-[min(90vh,760px)] w-full max-w-xl space-y-4 overflow-y-auto rounded-2xl border border-slate-700/80 p-5 shadow-2xl sm:p-6">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2.5">
                <span className="flex h-8 w-8 items-center justify-center rounded-lg border border-emerald-500/30 bg-emerald-500/12 text-emerald-400">
                  <Cpu className="h-4 w-4" />
                </span>
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-base font-semibold text-white">
                      Event #{drawerLog.id ?? "Trace"}
                    </span>
                    <span className="font-mono text-xs text-emerald-400">
                      · {drawerLog.category}
                    </span>
                  </div>
                </div>
              </div>
              <button
                onClick={() => setDrawerLog(null)}
                className="cursor-pointer rounded-lg border border-transparent p-1.5 text-slate-400 hover:border-slate-700 hover:bg-slate-800 hover:text-white"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            <div className="grid grid-cols-1 gap-2.5 text-xs sm:grid-cols-3">
              <div className="attroxx-well rounded-xl border border-slate-800 p-3">
                <div className="font-mono text-[10px] uppercase tracking-wider text-slate-500">
                  Verdict
                </div>
                <div
                  className={`mt-1 font-mono font-semibold ${
                    drawerLog.verdict === "BLOCKED"
                      ? "text-rose-400"
                      : "text-emerald-400"
                  }`}
                >
                  {drawerLog.verdict}
                </div>
              </div>
              <div className="attroxx-well rounded-xl border border-slate-800 p-3">
                <div className="font-mono text-[10px] uppercase tracking-wider text-slate-500">
                  Risk Score
                </div>
                <div className="mt-1 font-mono font-semibold text-white tabular-nums">
                  {Math.round(drawerLog.risk_score * 100)}%
                </div>
              </div>
              <div className="attroxx-well rounded-xl border border-slate-800 p-3">
                <div className="font-mono text-[10px] uppercase tracking-wider text-slate-500">
                  Latency
                </div>
                <div className="mt-1 font-mono font-semibold text-cyan-400 tabular-nums">
                  {drawerLog.total_latency_ms.toFixed(1)} ms
                </div>
              </div>
            </div>

            <div className="space-y-2">
              <div className="font-mono text-[11px] font-semibold uppercase tracking-wider text-slate-400">
                Raw Input
              </div>
              <pre className="attroxx-well max-h-48 overflow-y-auto whitespace-pre-wrap rounded-xl border border-slate-800 p-4 font-mono text-xs leading-relaxed text-slate-200">
                {drawerLog.raw_prompt}
              </pre>
            </div>

            <div className="flex justify-end gap-2.5 border-t border-slate-800/80 pt-3">
              {onSelectLog && (
                <button
                  onClick={() => {
                    onSelectLog(drawerLog);
                    setDrawerLog(null);
                  }}
                  className="cursor-pointer rounded-xl bg-gradient-to-r from-emerald-600 to-emerald-500 px-4 py-2 text-xs font-semibold text-white shadow-[0_6px_18px_rgba(16,185,129,0.24)] hover:from-emerald-500 hover:to-emerald-400"
                >
                  Open in Inspection Lab
                </button>
              )}
              <button
                onClick={() => setDrawerLog(null)}
                className="cursor-pointer rounded-xl border border-slate-700 bg-slate-800/90 px-4 py-2 text-xs font-medium text-slate-200 hover:bg-slate-700"
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
