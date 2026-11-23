"use client";

import React, { useMemo, useState } from "react";
import { Check, ChevronRight, Copy, Search, X } from "lucide-react";
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

export function TelemetryView({ auditLogs }: { auditLogs: SecurityTelemetry[] }) {
  const [simThreshold, setSimThreshold] = useState<number>(0.82);

  const taxonomyChartData = useMemo(() => {
    const counts: Record<string, number> = {};
    auditLogs
      .filter((l) => l.verdict === "BLOCKED")
      .forEach((l) => {
        const cat = l.category || "Uncategorized";
        counts[cat] = (counts[cat] || 0) + 1;
      });
    const entries = Object.entries(counts)
      .map(([name, count]) => ({ name, count }))
      .sort((a, b) => b.count - a.count);
    return entries.length > 0 ? entries : [{ name: "No Attacks Logged Yet", count: 0 }];
  }, [auditLogs]);

  const layerAttribution = useMemo(() => {
    const l1 = auditLogs.filter((l) => (l.blocked_layer || "").includes("L1")).length;
    const l2 = auditLogs.filter((l) => (l.blocked_layer || "").includes("L2")).length;
    const l3 = auditLogs.filter((l) => (l.blocked_layer || "").includes("L3")).length;
    const egress = auditLogs.filter((l) => (l.blocked_layer || "").includes("Egress")).length;
    return [
      { layer: "L1: Regex & Heuristics", count: l1, color: "text-amber-400" },
      { layer: "L2: Prompt Guard 2 ML", count: l2, color: "text-rose-400" },
      { layer: "L3: LLM-as-a-Judge", count: l3, color: "text-purple-400" },
      { layer: "Egress Canary Guard", count: egress, color: "text-cyan-400" },
    ];
  }, [auditLogs]);

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {layerAttribution.map((item) => (
          <div
            key={item.layer}
            className="glass-card border border-slate-800/90 rounded-xl p-4"
          >
            <p className="text-[11px] font-mono text-slate-400 uppercase">{item.layer}</p>
            <p className={`text-2xl font-bold font-mono mt-1.5 ${item.color}`}>{item.count}</p>
            <p className="text-[11px] text-slate-500 mt-0.5">Threats neutralized</p>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <div className="lg:col-span-7 glass-card border border-slate-800/90 rounded-xl p-4 sm:p-5">
          <h3 className="text-xs sm:text-sm font-semibold uppercase tracking-wider text-slate-300 mb-4">
            Blocked Attack Taxonomy Distribution
          </h3>
          <div className="h-72 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={taxonomyChartData} layout="vertical" margin={{ left: 10, right: 20 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis type="number" stroke="#64748b" fontSize={12} allowDecimals={false} />
                <YAxis type="category" dataKey="name" stroke="#94a3b8" fontSize={11} width={165} />
                <Tooltip
                  contentStyle={{ backgroundColor: "#050811", borderColor: "#334155", color: "#f8fafc" }}
                />
                <Bar dataKey="count" radius={[0, 6, 6, 0]}>
                  {taxonomyChartData.map((_, index) => (
                    <Cell key={`cell-${index}`} fill={index % 2 === 0 ? "#f43f5e" : "#06b6d4"} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="lg:col-span-5 glass-card border border-slate-800/90 rounded-xl p-4 sm:p-5 flex flex-col justify-between space-y-5">
          <div>
            <h3 className="text-xs sm:text-sm font-semibold uppercase tracking-wider text-slate-300 mb-2">
              Policy Sensitivity Simulator
            </h3>
            <p className="text-xs text-slate-400 leading-relaxed mb-4">
              Simulate how tightening or relaxing the Layer 2 risk cutoff alters ATTROXX verdicts
              across your captured traffic.
            </p>
            <div className="space-y-2">
              <div className="flex justify-between text-xs font-mono">
                <span className="text-slate-400">Block Cutoff Score:</span>
                <span className="text-emerald-400 font-bold">{(simThreshold * 100).toFixed(0)}%</span>
              </div>
              <input
                type="range"
                min="0.40"
                max="0.98"
                step="0.02"
                value={simThreshold}
                onChange={(e) => setSimThreshold(parseFloat(e.target.value))}
                className="w-full accent-emerald-500 cursor-pointer"
              />
            </div>
          </div>

          <div className="grid grid-cols-2 gap-3 pt-4 border-t border-slate-800">
            <div className="bg-[#050811] border border-slate-800 rounded-lg p-3">
              <p className="text-[11px] font-mono text-slate-400">WOULD BLOCK</p>
              <p className="text-xl font-bold font-mono text-rose-400 mt-1">
                {auditLogs.filter((l) => l.risk_score >= simThreshold).length}
              </p>
            </div>
            <div className="bg-[#050811] border border-slate-800 rounded-lg p-3">
              <p className="text-[11px] font-mono text-slate-400">WOULD ALLOW</p>
              <p className="text-xl font-bold font-mono text-emerald-400 mt-1">
                {auditLogs.filter((l) => l.risk_score < simThreshold).length}
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export function AuditLogsView({ auditLogs }: { auditLogs: SecurityTelemetry[] }) {
  const [logFilter, setLogFilter] = useState<"ALL" | "BLOCKED" | "ALLOWED">("ALL");
  const [searchQuery, setSearchQuery] = useState<string>("");
  const [selectedLog, setSelectedLog] = useState<SecurityTelemetry | null>(null);
  const [copiedJson, setCopiedJson] = useState<boolean>(false);

  const filteredLogs = useMemo(() => {
    return auditLogs.filter((log) => {
      const matchesVerdict = logFilter === "ALL" || log.verdict === logFilter;
      const matchesSearch =
        !searchQuery ||
        log.raw_prompt.toLowerCase().includes(searchQuery.toLowerCase()) ||
        (log.category || "").toLowerCase().includes(searchQuery.toLowerCase()) ||
        (log.blocked_layer || "").toLowerCase().includes(searchQuery.toLowerCase());
      return matchesVerdict && matchesSearch;
    });
  }, [auditLogs, logFilter, searchQuery]);

  const getSeverityBadge = (score: number, verdict: string) => {
    if (verdict !== "BLOCKED")
      return { label: "CLEAN", cls: "bg-slate-800 text-slate-400 border-slate-700" };
    if (score >= 0.95)
      return { label: "CRITICAL", cls: "bg-rose-500/20 text-rose-300 border-rose-500/40" };
    return { label: "HIGH", cls: "bg-amber-500/20 text-amber-300 border-amber-500/40" };
  };

  const copyEventJson = () => {
    if (!selectedLog) return;
    navigator.clipboard.writeText(JSON.stringify(selectedLog, null, 2));
    setCopiedJson(true);
    setTimeout(() => setCopiedJson(false), 1800);
  };

  return (
    <>
      <div className="glass-card border border-slate-800/90 rounded-xl p-4 sm:p-5 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            {(["ALL", "BLOCKED", "ALLOWED"] as const).map((status) => (
              <button
                key={status}
                onClick={() => setLogFilter(status)}
                className={`text-xs font-mono px-3 py-1.5 rounded-lg border transition cursor-pointer ${
                  logFilter === status
                    ? "bg-slate-800 text-white border-slate-600"
                    : "text-slate-400 border-slate-800 hover:text-slate-200"
                }`}
              >
                {status}
              </button>
            ))}
          </div>

          <div className="relative w-full sm:w-72">
            <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search category, layer, payload..."
              className="w-full pl-9 pr-3 py-1.5 text-xs bg-[#050811] border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:border-emerald-500"
            />
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse min-w-[740px]">
            <thead>
              <tr className="border-b border-slate-800 text-[11px] font-mono uppercase text-slate-400">
                <th className="py-2.5 px-3">ID</th>
                <th className="py-2.5 px-3">Severity</th>
                <th className="py-2.5 px-3">Verdict</th>
                <th className="py-2.5 px-3">Category</th>
                <th className="py-2.5 px-3">Trigger Layer</th>
                <th className="py-2.5 px-3">Risk</th>
                <th className="py-2.5 px-3">Latency</th>
                <th className="py-2.5 px-3">Payload Snippet</th>
                <th className="py-2.5 px-3"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-xs">
              {filteredLogs.map((log) => {
                const sev = getSeverityBadge(log.risk_score, log.verdict);
                return (
                  <tr
                    key={log.id}
                    onClick={() => setSelectedLog(log)}
                    className="hover:bg-slate-800/40 cursor-pointer transition"
                  >
                    <td className="py-3 px-3 font-mono text-slate-400">#{log.id}</td>
                    <td className="py-3 px-3">
                      <span className={`font-mono px-2 py-0.5 rounded text-[10px] border ${sev.cls}`}>
                        {sev.label}
                      </span>
                    </td>
                    <td className="py-3 px-3">
                      <span
                        className={`font-mono px-2 py-0.5 rounded text-[11px] border ${
                          log.verdict === "BLOCKED"
                            ? "bg-rose-500/15 text-rose-400 border-rose-500/30"
                            : "bg-emerald-500/15 text-emerald-400 border-emerald-500/30"
                        }`}
                      >
                        {log.verdict}
                      </span>
                    </td>
                    <td className="py-3 px-3 text-slate-200 font-medium">{log.category}</td>
                    <td className="py-3 px-3 font-mono text-slate-400">
                      {log.blocked_layer || "Passed All"}
                    </td>
                    <td className="py-3 px-3 font-mono text-slate-200">
                      {(log.risk_score * 100).toFixed(1)}%
                    </td>
                    <td className="py-3 px-3 font-mono text-slate-400">{log.total_latency_ms} ms</td>
                    <td className="py-3 px-3 font-mono text-slate-400 max-w-xs truncate">
                      {log.raw_prompt}
                    </td>
                    <td className="py-3 px-3 text-right">
                      <ChevronRight className="w-4 h-4 text-slate-500 inline" />
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {selectedLog && (
        <div className="fixed inset-0 bg-black/75 backdrop-blur-xs z-50 flex justify-end">
          <div className="w-full sm:max-w-lg bg-[#090f1e] border-l border-slate-800 h-full p-5 sm:p-6 overflow-y-auto space-y-5">
            <div className="flex items-center justify-between border-b border-slate-800 pb-4">
              <div>
                <span className="text-xs font-mono text-cyan-400">
                  ATTROXX EVENT #{selectedLog.id} • {selectedLog.source}
                </span>
                <h3 className="text-base font-bold text-white mt-0.5">{selectedLog.category}</h3>
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={copyEventJson}
                  className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-mono text-slate-200 cursor-pointer"
                >
                  {copiedJson ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  {copiedJson ? "Copied" : "JSON"}
                </button>
                <button
                  onClick={() => setSelectedLog(null)}
                  className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 cursor-pointer"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>
            </div>

            <div className="space-y-2">
              <p className="text-xs font-mono text-slate-400">RAW INPUT PAYLOAD</p>
              <pre className="text-xs font-mono bg-[#050811] border border-slate-800 p-3 rounded-lg whitespace-pre-wrap break-words text-slate-200">
                {selectedLog.raw_prompt}
              </pre>
            </div>

            <div className="space-y-2">
              <p className="text-xs font-mono text-slate-400">NORMALIZED INSPECTION BUFFER</p>
              <pre className="text-xs font-mono bg-[#050811] border border-slate-800 p-3 rounded-lg whitespace-pre-wrap break-words text-amber-300/90">
                {selectedLog.normalized_prompt}
              </pre>
            </div>

            <div className="space-y-2">
              <p className="text-xs font-mono text-slate-400">STAGE EXECUTION TRACE</p>
              {selectedLog.stages.map((st, i) => (
                <div
                  key={i}
                  className="bg-[#050811] border border-slate-800 p-3 rounded-lg text-xs space-y-1"
                >
                  <div className="flex justify-between font-mono">
                    <span className="text-white font-semibold">{st.name}</span>
                    <span className="text-slate-400">
                      {st.status} • {st.latency_ms} ms
                    </span>
                  </div>
                  <p className="text-slate-400 font-mono break-words">{st.detail}</p>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </>
  );
}