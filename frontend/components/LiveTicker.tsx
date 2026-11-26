"use client";

import React from "react";
import type { SecurityTelemetry } from "./AttackLabTab";

export default function LiveTicker({
  events,
  onSelectEvent,
}: {
  events: SecurityTelemetry[];
  onSelectEvent: (ev: SecurityTelemetry) => void;
}) {
  const recent = events.slice(0, 8);

  return (
    <div className="flex items-center gap-3 border-b border-slate-800/80 bg-[#080d16]/95 px-4 py-2 lg:px-5">
      <div className="flex shrink-0 items-center gap-2 border-r border-slate-800/90 pr-3 font-mono text-[10px] font-semibold uppercase tracking-[0.16em] text-emerald-300">
        <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 shadow-[0_0_8px_#10b981] animate-pulse" />
        <span>Live Traffic</span>
      </div>

      {recent.length === 0 ? (
        <span className="font-mono text-xs text-slate-500">
          Waiting for incoming gateway requests...
        </span>
      ) : (
        <div className="attroxx-ticker flex min-w-0 flex-1 items-center gap-2 overflow-x-auto">
          {recent.map((ev, idx) => {
            const isBlocked = ev.verdict === "BLOCKED";
            return (
              <button
                key={`${ev.id ?? "ev"}-${idx}`}
                onClick={() => onSelectEvent(ev)}
                className={`group flex shrink-0 cursor-pointer items-center gap-2 rounded-lg border bg-[#070b13] px-2.5 py-1 text-xs shadow-[inset_0_1px_0_rgba(255,255,255,0.03)] hover:bg-slate-800/75 ${
                  isBlocked
                    ? "border-rose-500/30 hover:border-rose-400/50"
                    : "border-emerald-500/25 hover:border-emerald-400/45"
                }`}
              >
                <span
                  className={`h-1.5 w-1.5 rounded-full ${
                    isBlocked ? "bg-rose-400" : "bg-emerald-400"
                  }`}
                />
                <span className="font-mono text-[11px] text-slate-500 group-hover:text-slate-400">
                  #{ev.id ?? recent.length - idx}
                </span>
                <span className="max-w-[140px] truncate font-medium text-slate-100">
                  {ev.category || (isBlocked ? "Blocked Threat" : "Benign")}
                </span>
                <span className="rounded bg-slate-900/90 px-1.5 py-0.5 font-mono text-[10px] text-slate-400 tabular-nums">
                  {ev.total_latency_ms.toFixed(1)}ms
                </span>
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}
