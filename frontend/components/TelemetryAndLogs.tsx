"use client";

import React, { useMemo, useState } from "react";
import { Search, ShieldAlert, ShieldCheck, X } from "lucide-react";
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
    return Object.entries(counts)
      .map(([name, count]) => ({ name, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 6);
  }, [auditLogs]);

  const layerBreakdown = useMemo(() => {
    const counts: Record<string, number> = {};
    auditLogs
      .filter((l) => l.verdict === "BLOCKED")
      .forEach((l) => {
        const layer = l.blocked_layer || "L1 Deterministic";
        counts[layer] = (counts[layer] || 0) + 1;
      });
    return Object.entries(counts);
  }, [auditLogs]);

  const simulatedBlocks = useMemo(() => {
    return auditLogs.filter((l) => l.risk_score >= simThreshold).length;
  }, [auditLogs, simThreshold]);

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Attack Taxonomy Bar Chart */}
        <div className="lg:col-span-7 p-5 rounded-lg bg-[#111113] border border-zinc-800 space-y-4">
          <div>
            <h2 className="text-sm font-semibold text-white">
              Blocked Threat Taxonomy
            </h2>
            <p className="text-xs text-zinc-500 mt-0.5">
              Distribution of intercepted attack categories
            </p>
          </div>

          <div className="h-64">
            {taxonomyChartData.length === 0 ? (
              <div className="h-full flex items-center justify-center text-xs text-zinc-500">
                No blocked attacks recorded yet. Run test vectors in Inspection Lab.
              </div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart
                  data={taxonomyChartData}
                  layout="vertical"
                  margin={{ top: 4, right: 20, left: 10, bottom: 4 }}
                >
                  <CartesianGrid stroke="#27272a" strokeDasharray="3 3" horizontal={false} />
                  <XAxis type="number" stroke="#71717a" fontSize={12} allowDecimals={false} />
                  <YAxis
                    type="category"
                    dataKey="name"
                    stroke="#a1a1aa"
                    fontSize={12}
                    width={150}
                  />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "#09090b",
                      borderColor: "#27272a",
                      borderRadius: "6px",
                      fontSize: "12px",
                      color: "#fafafa",
                    }}
                  />
                  <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                    {taxonomyChartData.map((_, i) => (
                      <Cell key={i} fill="#e4e4e7" />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>

        {/* Defense Layer Efficacy & Threshold Simulator */}
        <div className="lg:col-span-5 space-y-6">
          <div className="p-5 rounded-lg bg-[#111113] border border-zinc-800 space-y-3">
            <div>
              <h2 className="text-sm font-semibold text-white">
                Enforcement by Layer
              </h2>
              <p className="text-xs text-zinc-500 mt-0.5">
                Where threats were stopped in the pipeline
              </p>
            </div>

            {layerBreakdown.length === 0 ? (
              <p className="text-xs text-zinc-500 py-4">
                No layer blocks logged yet.
              </p>
            ) : (
              <div className="space-y-2.5 pt-1">
                {layerBreakdown.map(([layer, count]) => (
                  <div
                    key={layer}
                    className="flex items-center justify-between px-3 py-2 rounded-md bg-zinc-950 border border-zinc-800 text-xs"
                  >
                    <span className="text-zinc-200 font-medium">{layer}</span>
                    <span className="font-mono text-zinc-400">
                      {count} blocked
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>

          <div className="p-5 rounded-lg bg-[#111113] border border-zinc-800 space-y-3">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-sm font-semibold text-white">
                  Threshold Simulator
                </h2>
                <p className="text-xs text-zinc-500 mt-0.5">
                  Preview block sensitivity on logged traffic
                </p>
              </div>
              <span className="text-xs font-mono px-2 py-1 rounded bg-zinc-950 border border-zinc-800 text-zinc-200">
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
              className="w-full accent-white cursor-pointer"
            />

            <div className="flex items-center justify-between text-xs text-zinc-400 pt-1">
              <span>Projected blocks at threshold:</span>
              <span className="font-mono font-semibold text-white">
                {simulatedBlocks} / {auditLogs.length} requests
              </span>
            </div>
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
    <div className="p-5 rounded-lg bg-[#111113] border border-zinc-800 space-y-4">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h2 className="text-sm font-semibold text-white">Incident Ledger</h2>
          <p className="text-xs text-zinc-500 mt-0.5">
            Click any row to inspect full stage telemetry
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-zinc-500 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Filter payloads..."
              className="pl-8 pr-3 py-1.5 rounded-md bg-zinc-950 border border-zinc-800 text-xs text-zinc-200 placeholder-zinc-600 focus:outline-none focus:border-zinc-600"
            />
          </div>

          {(["ALL", "BLOCKED", "ALLOWED"] as const).map((status) => (
            <button
              key={status}
              onClick={() => setFilter(status)}
              className={`px-2.5 py-1.5 rounded-md text-xs font-medium border transition-colors cursor-pointer ${
                filter === status
                  ? "bg-zinc-800 border-zinc-600 text-white"
                  : "bg-zinc-950 border-zinc-800 text-zinc-400 hover:text-zinc-200"
              }`}
            >
              {status}
            </button>
          ))}
        </div>
      </div>

      {/* Clean Table */}
      <div className="overflow-x-auto border border-zinc-800 rounded-md">
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="border-b border-zinc-800 bg-zinc-950 text-[11px] font-medium uppercase tracking-wider text-zinc-500">
              <th className="py-2.5 px-3.5">Verdict</th>
              <th className="py-2.5 px-3.5">Category</th>
              <th className="py-2.5 px-3.5">Payload Preview</th>
              <th className="py-2.5 px-3.5">Risk</th>
              <th className="py-2.5 px-3.5 text-right">Latency</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-zinc-800/80 text-xs">
            {filteredLogs.length === 0 ? (
              <tr>
                <td colSpan={5} className="py-8 text-center text-zinc-500">
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
                    className="hover:bg-zinc-900/70 transition-colors cursor-pointer"
                  >
                    <td className="py-2.5 px-3.5 whitespace-nowrap">
                      <span
                        className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded font-medium ${
                          blocked
                            ? "bg-red-500/10 text-red-400"
                            : "bg-emerald-500/10 text-emerald-400"
                        }`}
                      >
                        {blocked ? (
                          <ShieldAlert className="w-3 h-3" />
                        ) : (
                          <ShieldCheck className="w-3 h-3" />
                        )}
                        {log.verdict}
                      </span>
                    </td>
                    <td className="py-2.5 px-3.5 text-zinc-200 font-medium whitespace-nowrap">
                      {log.category || "Benign"}
                    </td>
                    <td className="py-2.5 px-3.5 font-mono text-zinc-400 max-w-md truncate">
                      {log.raw_prompt}
                    </td>
                    <td className="py-2.5 px-3.5 font-mono text-zinc-300">
                      {Math.round(log.risk_score * 100)}%
                    </td>
                    <td className="py-2.5 px-3.5 font-mono text-zinc-400 text-right whitespace-nowrap">
                      {log.total_latency_ms.toFixed(1)} ms
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      {/* Detail Modal */}
      {drawerLog && (
        <div className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4">
          <div className="max-w-xl w-full rounded-lg bg-[#111113] border border-zinc-800 p-5 space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span className="text-sm font-semibold text-white">
                  Event #{drawerLog.id ?? "Trace"}
                </span>
                <span className="text-xs font-mono text-zinc-500">
                  · {drawerLog.category}
                </span>
              </div>
              <button
                onClick={() => setDrawerLog(null)}
                className="p-1 rounded hover:bg-zinc-800 text-zinc-400 cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-1.5">
              <div className="text-xs text-zinc-400">Raw Input</div>
              <pre className="p-3 rounded bg-zinc-950 border border-zinc-800 text-xs font-mono text-zinc-200 whitespace-pre-wrap max-h-40 overflow-y-auto">
                {drawerLog.raw_prompt}
              </pre>
            </div>

            <div className="flex justify-end gap-2">
              {onSelectLog && (
                <button
                  onClick={() => {
                    onSelectLog(drawerLog);
                    setDrawerLog(null);
                  }}
                  className="px-3 py-1.5 rounded-md text-xs font-medium bg-white text-zinc-950 hover:bg-zinc-200 cursor-pointer"
                >
                  Open in Inspection Lab
                </button>
              )}
              <button
                onClick={() => setDrawerLog(null)}
                className="px-3 py-1.5 rounded-md text-xs font-medium bg-zinc-900 border border-zinc-800 text-zinc-300 cursor-pointer"
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
