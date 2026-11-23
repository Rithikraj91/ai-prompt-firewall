"use client";

import React from "react";
import { Radio, ShieldAlert, ShieldCheck } from "lucide-react";
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
    <div className="border-b border-slate-800/80 bg-[#04070f]/95 backdrop-blur-md">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 py-2 flex items-center gap-3 overflow-x-auto">
        <div className="flex items-center gap-1.5 text-[10px] font-mono font-bold tracking-wider text-cyan-400 shrink-0 pr-2 border-r border-slate-800">
          <Radio className="w-3.5 h-3.5 text-emerald-400 animate-pulse" />
          LIVE FEED
        </div>

        {recent.length === 0 ? (
          <span className="text-[11px] font-mono text-slate-500">
            Listening for gateway traffic on /v1/events/stream...
          </span>
        ) : (
          <div className="flex items-center gap-2">
            {recent.map((ev, idx) => {
              const blocked = ev.verdict === "BLOCKED";
              return (
                <button
                  key={ev.id ?? idx}
                  onClick={() => onSelectEvent(ev)}
                  className={`flex items-center gap-1.5 px-2.5 py-1 rounded-md text-[11px] font-mono whitespace-nowrap border transition cursor-pointer ${
                    blocked
                      ? "bg-rose-950/30 border-rose-500/30 text-rose-300 hover:bg-rose-950/50"
                      : "bg-emerald-950/20 border-emerald-500/25 text-emerald-300 hover:bg-emerald-950/40"
                  }`}
                >
                  {blocked ? (
                    <ShieldAlert className="w-3 h-3 text-rose-400 shrink-0" />
                  ) : (
                    <ShieldCheck className="w-3 h-3 text-emerald-400 shrink-0" />
                  )}
                  <span className="font-bold">#{ev.id}</span>
                  <span>{ev.category}</span>
                  <span className="text-slate-500">• {ev.total_latency_ms}ms</span>
                </button>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}