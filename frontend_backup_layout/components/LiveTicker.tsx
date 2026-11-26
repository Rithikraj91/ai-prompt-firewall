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
    <div className="border-b border-slate-800 bg-[#0c141b] px-6 lg:px-8 py-3 flex items-center gap-4 overflow-x-auto">
      <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-emerald-400 shrink-0 pr-4 border-r border-slate-800">
        <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
        <span>Live Traffic</span>
      </div>

      {recent.length === 0 ? (
        <span className="text-sm text-slate-400">
          Waiting for incoming gateway requests...
        </span>
      ) : (
        <div className="flex items-center gap-2.5">
          {recent.map((ev, idx) => {
            const isBlocked = ev.verdict === "BLOCKED";
            return (
              <button
                key={`${ev.id ?? 'ev'}-${idx}`}
                onClick={() => onSelectEvent(ev)}
                className="flex items-center gap-2.5 px-3 py-1.5 rounded-lg text-xs bg-[#0b1117]/90 hover:bg-slate-800 border border-slate-800 hover:border-slate-800/80 transition-colors shrink-0 cursor-pointer"
              >
                <span
                  className={`w-2 h-2 rounded-full ${
                    isBlocked ? "bg-rose-500" : "bg-emerald-400"
                  }`}
                />
                <span className="font-mono text-slate-400">
                  #{ev.id ?? recent.length - idx}
                </span>
                <span className="text-slate-100 font-medium truncate max-w-[190px]">
                  {ev.category || (isBlocked ? "Blocked Threat" : "Benign")}
                </span>
                <span className="font-mono text-slate-400">
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
