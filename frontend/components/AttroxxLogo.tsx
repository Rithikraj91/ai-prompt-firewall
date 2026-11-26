import React from "react";

interface AttroxxLogoProps {
  className?: string;
}

export function AttroxxLogo({ className = "" }: AttroxxLogoProps) {
  return (
    <div
      className={`group relative flex w-full min-w-0 items-center gap-3 overflow-hidden rounded-xl border border-emerald-400/25 bg-gradient-to-br from-[#0b1522] via-[#080f1a] to-[#060a12] px-3 py-2.5 shadow-[inset_0_1px_0_rgba(110,231,183,0.12),inset_0_-1px_0_rgba(34,211,238,0.08),0_10px_24px_-10px_rgba(0,0,0,0.65)] select-none ${className}`}
    >
      {/* Subtle emerald/cyan edge lighting */}
      <span
        className="pointer-events-none absolute inset-x-3 top-0 h-px bg-gradient-to-r from-emerald-400/60 via-cyan-300/45 to-transparent"
        aria-hidden="true"
      />
      <span
        className="pointer-events-none absolute inset-y-2 left-0 w-px bg-gradient-to-b from-emerald-400/50 via-cyan-400/20 to-transparent"
        aria-hidden="true"
      />

      {/* Boxed geometric "A" emblem */}
      <div
        className="relative flex h-9 w-9 shrink-0 items-center justify-center rounded-lg shadow-[0_6px_16px_rgba(0,0,0,0.45)]"
        aria-hidden="true"
      >
        <svg
          width="36"
          height="36"
          viewBox="0 0 32 32"
          fill="none"
          xmlns="http://www.w3.org/2000/svg"
        >
          <defs>
            <linearGradient id="attroxx-box-bg" x1="2" y1="2" x2="30" y2="30" gradientUnits="userSpaceOnUse">
              <stop offset="0%" stopColor="#0C201B" />
              <stop offset="100%" stopColor="#050B12" />
            </linearGradient>
            <linearGradient id="attroxx-box-stroke" x1="2" y1="2" x2="30" y2="30" gradientUnits="userSpaceOnUse">
              <stop offset="0%" stopColor="#6EE7B7" stopOpacity="0.9" />
              <stop offset="50%" stopColor="#10B981" stopOpacity="0.6" />
              <stop offset="100%" stopColor="#22D3EE" stopOpacity="0.85" />
            </linearGradient>
            <linearGradient id="attroxx-a-frame" x1="16" y1="6.5" x2="16" y2="25" gradientUnits="userSpaceOnUse">
              <stop offset="0%" stopColor="#FFFFFF" />
              <stop offset="65%" stopColor="#D1FAE5" />
              <stop offset="100%" stopColor="#6EE7B7" />
            </linearGradient>
            <linearGradient id="attroxx-a-gate" x1="11.5" y1="18" x2="20.5" y2="21" gradientUnits="userSpaceOnUse">
              <stop offset="0%" stopColor="#34D399" />
              <stop offset="50%" stopColor="#22D3EE" />
              <stop offset="100%" stopColor="#67E8F9" />
            </linearGradient>
          </defs>

          <rect
            x="1.5"
            y="1.5"
            width="29"
            height="29"
            rx="7"
            fill="url(#attroxx-box-bg)"
            stroke="url(#attroxx-box-stroke)"
            strokeWidth="1.4"
          />
          <rect
            x="3.75"
            y="3.75"
            width="24.5"
            height="24.5"
            rx="5"
            stroke="#34D399"
            strokeOpacity="0.2"
            strokeWidth="0.75"
          />

          <path
            d="M14.3 7.1H17.7L24.6 24.4H21.1L16 11.4L10.9 24.4H7.4L14.3 7.1Z"
            fill="url(#attroxx-a-frame)"
          />
          <path
            d="M12.2 18.6H19.8L19.1 20.9H12.9L12.2 18.6Z"
            fill="url(#attroxx-a-gate)"
          />
          <path
            d="M16 14.3L17.3 16.4H14.7L16 14.3Z"
            fill="#22D3EE"
          />
        </svg>
      </div>

      {/* Wordmark + Subtitle */}
      <div className="min-w-0 flex-1 leading-none">
        <div className="truncate text-[1.18rem] font-semibold tracking-[0.16em] text-white">
          ATTRO
          <span className="bg-gradient-to-r from-emerald-300 to-cyan-300 bg-clip-text text-transparent">
            XX
          </span>
        </div>
        <div className="mt-1.5 flex items-center gap-1.5">
          <span className="h-px w-3 shrink-0 bg-gradient-to-r from-emerald-400 to-cyan-400" />
          <span className="truncate font-mono text-[9.5px] font-semibold uppercase tracking-[0.15em] text-slate-400">
            RUNTIME AI FIREWALL
          </span>
        </div>
      </div>
    </div>
  );
}
