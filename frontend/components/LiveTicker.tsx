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
    <div className="border-b border-zinc-800 bg-zinc-950">
      <div className="px-6 py-2.5 flex items-center gap-3 overflow-x-auto">
        <div className="flex items-center gap-2 text-xs font-medium text-zinc-400 shrink-0 pr-3 border-r border-zinc-800">
          <span className="w-2 h-2 rounded-full bg-emerald-500" />
          <span>Live Feed</span>
        </div>

        {recent.length === 0 ? (
          <span className="text-xs text-zinc-500">
            Waiting for incoming gateway traffic...
          </span>
        ) : (
          <div className="flex items-center gap-2">
            {recent.map((ev, idx) => {
              const isBlocked = ev.verdict === "BLOCKED";
              return (
                <button
                  key={ev.id ?? idx}
                  onClick={() => onSelectEvent(ev)}
                  className="flex items-center gap-2 px-2.5 py-1 rounded-md text-xs bg-zinc-900 hover:bg-zinc-800 border border-zinc-800 transition-colors shrink-0 cursor-pointer"
                >
                  <span
                    className={`w-1.5 h-1.5 rounded-full ${
                      isBlocked ? "bg-red-500" : "bg-emerald-500"
                    }`}
                  />
                  <span className="font-mono text-zinc-500">
                    #{ev.id ?? recent.length - idx}
                  </span>
                  <span className="text-zinc-200 font-medium truncate max-w-[160px]">
                    {ev.category || (isBlocked ? "Blocked" : "Benign")}
                  </span>
                  <span className="font-mono text-zinc-500">
                    {ev.total_latency_ms.toFixed(1)}ms
                  </span>
                </button>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
