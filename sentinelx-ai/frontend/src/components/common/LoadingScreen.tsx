import { ShieldCheckIcon } from "@heroicons/react/24/outline";

export default function LoadingScreen() {
  return (
    <div className="min-h-screen bg-[var(--color-surface-50)] flex items-center justify-center p-6">
      <div className="flex flex-col items-center gap-4 animate-pulse">
        <div className="w-16 h-16 rounded-2xl bg-gradient-to-br from-[var(--color-primary-500)]/20 to-[var(--color-secondary-500)]/20 border border-[var(--color-primary-500)]/40 flex items-center justify-center shadow-[0_0_30px_rgba(0,229,255,0.2)]">
          <ShieldCheckIcon className="w-9 h-9 text-[var(--color-primary-500)] animate-spin" />
        </div>
        <div className="text-center">
          <p className="text-sm font-bold text-[var(--color-text-primary)] tracking-wide">SentinelX AI</p>
          <p className="text-[11px] font-mono text-[var(--color-primary-500)] mt-1">Authenticating Security Credentials...</p>
        </div>
      </div>
    </div>
  );
}
