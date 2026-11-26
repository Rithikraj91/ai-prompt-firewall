import React from "react";

interface AttroxxLogoProps {
  className?: string;
}

export function AttroxxLogo({ className = "" }: AttroxxLogoProps) {
  return (
    <div
      className={`group relative flex items-center gap-3 rounded-2xl border border-emerald-500/20 bg-gradient-to-br from-emerald-950/35 via-slate-900/90 to-slate-950/95 px-2.5 py-3 shadow-[0_8px_30px_rgba(0,0,0,0.45),inset_0_1px_0_rgba(255,255,255,0.08)] transition-all duration-300 hover:border-emerald-400/40 hover:shadow-[0_0_28px_rgba(16,185,129,0.2)] select-none ${className}`}
    >
      {/* Ambient top-edge emerald highlight */}
      <span className="pointer-events-none absolute inset-x-6 top-0 h-[1px] bg-gradient-to-r from-transparent via-emerald-400/50 to-transparent" />

      {/* 48x48 Layered Cyber-Shield Emblem */}
      <div className="relative flex h-12 w-12 shrink-0 items-center justify-center rounded-xl border border-emerald-400/30 bg-gradient-to-b from-emerald-500/20 via-slate-900 to-slate-950 shadow-[0_0_24px_rgba(16,185,129,0.25),inset_0_1px_0_rgba(255,255,255,0.16)] transition-transform duration-300 group-hover:scale-[1.03]">
        <span className="pointer-events-none absolute top-1.5 left-1.5 h-2 w-2 border-t-[1.5px] border-l-[1.5px] border-emerald-300/75 rounded-tl-[2px]" />
        <span className="pointer-events-none absolute bottom-1.5 right-1.5 h-2 w-2 border-b-[1.5px] border-r-[1.5px] border-cyan-300/75 rounded-br-[2px]" />

        <svg
          width="30"
          height="30"
          viewBox="0 0 32 32"
          fill="none"
          xmlns="http://www.w3.org/2000/svg"
          aria-hidden="true"
          className="drop-shadow-[0_0_10px_rgba(52,211,153,0.55)]"
        >
          <defs>
            <linearGradient id="attroxx-hex" x1="4" y1="2" x2="28" y2="30" gradientUnits="userSpaceOnUse">
              <stop offset="0%" stopColor="#A7F3D0" />
              <stop offset="50%" stopColor="#10B981" />
              <stop offset="100%" stopColor="#22D3EE" />
            </linearGradient>
            <linearGradient id="attroxx-fill" x1="6" y1="4" x2="26" y2="28" gradientUnits="userSpaceOnUse">
              <stop offset="0%" stopColor="#10B981" stopOpacity="0.32" />
              <stop offset="100%" stopColor="#020617" stopOpacity="0.92" />
            </linearGradient>
          </defs>

          <path
            d="M16 2.2L27.8 8.3V16.8C27.8 23.6 22.8 28.8 16 30.5C9.2 28.8 4.2 23.6 4.2 16.8V8.3L16 2.2Z"
            fill="url(#attroxx-fill)"
            stroke="url(#attroxx-hex)"
            strokeWidth="2"
          />

          <path
            d="M16 5.6L24.6 10.1V16.5C24.6 21.5 21 25.4 16 26.8C11 25.4 7.4 21.5 7.4 16.5V10.1L16 5.6Z"
            stroke="#6EE7B7"
            strokeOpacity="0.35"
            strokeWidth="1"
          />

          <path
            d="M16 9.2L21.8 21.8H18.9L17.7 19H14.3L13.1 21.8H10.2L16 9.2ZM15.1 16.8H16.9L16 14.7L15.1 16.8Z"
            fill="#FFFFFF"
          />
          <path
            d="M11.8 12.2L20.2 20.6M20.2 12.2L11.8 20.6"
            stroke="#34D399"
            strokeWidth="1.6"
            strokeLinecap="round"
            strokeOpacity="0.9"
          />
        </svg>
      </div>

      {/* Large ATTROXX Wordmark + Full-Width Subtitle */}
      <div className="flex flex-col leading-none">
        <span className="text-[26px] font-black tracking-[0.11em] text-white drop-shadow-[0_2px_10px_rgba(16,185,129,0.22)]">
          ATTRO
          <span className="bg-gradient-to-r from-emerald-300 via-teal-300 to-cyan-300 bg-clip-text text-transparent">
            XX
          </span>
        </span>

        <div className="mt-2 flex items-center gap-1.5">
          <span className="relative flex h-1.5 w-1.5 shrink-0">
            <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-60" />
            <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-emerald-400 shadow-[0_0_8px_#34D399]" />
          </span>
          <span className="whitespace-nowrap text-[9.5px] font-bold uppercase tracking-[0.13em] text-emerald-300/90">
            Runtime AI Firewall
          </span>
        </div>
      </div>
    </div>
  );
}
