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
    <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
      <div className="lg:col-span-7 p-6 rounded-xl bg-[#111827] border border-slate-800 space-y-4">
        <div>
          <h2 className="text-lg font-semibold text-white">
            Blocked Threat Taxonomy
          </h2>
          <p className="text-sm text-slate-400 mt-0.5">
            Distribution of intercepted attack categories
          </p>
        </div>

        <div className="h-72">
          {taxonomyChartData.length === 0 ? (
            <div className="h-full flex items-center justify-center text-sm text-slate-400">
              No blocked attacks recorded yet. Run test vectors in Inspection Lab.
            </div>
          ) : (
            <ResponsiveContainer width="100%" height="100%">
              <BarChart
                data={taxonomyChartData}
                layout="vertical"
                margin={{ top: 4, right: 20, left: 10, bottom: 4 }}
              >
                <CartesianGrid stroke="#1e293b" strokeDasharray="3 3" horizontal={false} />
                <XAxis type="number" stroke="#94a3b8" fontSize={12} allowDecimals={false} />
                <YAxis
                  type="category"
                  dataKey="name"
                  stroke="#cbd5e1"
                  fontSize={12}
                  width={160}
                />
                <Tooltip
                  contentStyle={{
                    backgroundColor: "#0b0f19",
                    borderColor: "#334155",
                    borderRadius: "8px",
                    fontSize: "12px",
                    color: "#f8fafc",
                  }}
                />
                <Bar dataKey="count" radius={[0, 6, 6, 0]}>
                  {taxonomyChartData.map((_, i) => (
                    <Cell key={i} fill="#6366f1" />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>

      <div className="lg:col-span-5 space-y-6">
        <div className="p-6 rounded-xl bg-[#111827] border border-slate-800 space-y-3.5">
          <div>
            <h2 className="text-lg font-semibold text-white">
              Enforcement by Layer
            </h2>
            <p className="text-sm text-slate-400 mt-0.5">
              Where threats were stopped in the pipeline
            </p>
          </div>

          {layerBreakdown.length === 0 ? (
            <p className="text-sm text-slate-400 py-4">
              No layer blocks logged yet.
            </p>
          ) : (
            <div className="space-y-2.5 pt-1">
              {layerBreakdown.map(([layer, count]) => (
                <div
                  key={layer}
                  className="flex items-center justify-between px-4 py-2.5 rounded-lg bg-[#0b0f19] border border-slate-800 text-sm"
                >
                  <span className="text-slate-200 font-medium">{layer}</span>
                  <span className="font-mono text-rose-400 font-semibold">
                    {count} blocked
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="p-6 rounded-xl bg-[#111827] border border-slate-800 space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-lg font-semibold text-white">
                Threshold Simulator
              </h2>
              <p className="text-sm text-slate-400 mt-0.5">
                Preview sensitivity on logged traffic
              </p>
            </div>
            <span className="text-sm font-mono font-semibold px-3 py-1 rounded-md bg-[#0b0f19] border border-slate-700 text-indigo-300">
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
            className="w-full accent-indigo-500 cursor-pointer"
          />

          <div className="flex items-center justify-between text-sm text-slate-300 pt-1">
            <span>Projected blocks at threshold:</span>
            <span className="font-mono font-semibold text-white">
              {simulatedBlocks} / {auditLogs.length} requests
            </span>
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
    <div className="p-6 rounded-xl bg-[#111827] border border-slate-800 space-y-5">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h2 className="text-lg font-semibold text-white">Incident Ledger</h2>
          <p className="text-sm text-slate-400 mt-0.5">
            Click any row to inspect full stage telemetry
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          <div className="relative">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Filter payloads..."
              className="pl-9 pr-3 py-2 rounded-lg bg-[#0b0f19] border border-slate-700 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-indigo-500"
            />
          </div>

          {(["ALL", "BLOCKED", "ALLOWED"] as const).map((status) => (
            <button
              key={status}
              onClick={() => setFilter(status)}
              className={`px-3 py-2 rounded-lg text-xs font-semibold border transition-colors cursor-pointer ${
                filter === status
                  ? "bg-indigo-600/20 border-indigo-500 text-white"
                  : "bg-[#0b0f19] border-slate-700 text-slate-400 hover:text-slate-200"
              }`}
            >
              {status}
            </button>
          ))}
        </div>
      </div>

      <div className="overflow-x-auto border border-slate-800 rounded-lg">
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="border-b border-slate-800 bg-[#0b0f19] text-xs font-semibold uppercase tracking-wider text-slate-400">
              <th className="py-3 px-4">Verdict</th>
              <th className="py-3 px-4">Category</th>
              <th className="py-3 px-4">Payload Preview</th>
              <th className="py-3 px-4">Risk</th>
              <th className="py-3 px-4 text-right">Latency</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/80 text-sm">
            {filteredLogs.length === 0 ? (
              <tr>
                <td colSpan={5} className="py-10 text-center text-slate-400">
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
                    className="hover:bg-slate-800/50 transition-colors cursor-pointer"
                  >
                    <td className="py-3 px-4 whitespace-nowrap">
                      <span
                        className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-semibold ${
                          blocked
                            ? "bg-rose-500/15 text-rose-400"
                            : "bg-emerald-500/15 text-emerald-400"
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
        <div className="fixed inset-0 z-50 bg-black/75 flex items-center justify-center p-4">
          <div className="max-w-xl w-full rounded-xl bg-[#111827] border border-slate-700 p-6 space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span className="text-base font-semibold text-white">
                  Event #{drawerLog.id ?? "Trace"}
                </span>
                <span className="text-xs font-mono text-indigo-400">
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

            <div className="space-y-2">
              <div className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                Raw Input
              </div>
              <pre className="p-4 rounded-lg bg-[#0b0f19] border border-slate-800 text-xs font-mono text-slate-200 whitespace-pre-wrap max-h-48 overflow-y-auto">
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
                  className="px-4 py-2 rounded-lg text-xs font-semibold bg-indigo-600 text-white hover:bg-indigo-500 cursor-pointer"
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
