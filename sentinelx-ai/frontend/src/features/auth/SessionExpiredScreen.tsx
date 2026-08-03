import { Link } from "react-router-dom";
import { ClockIcon } from "@heroicons/react/24/outline";

export default function SessionExpiredScreen() {
  return (
    <div className="min-h-screen bg-[var(--color-surface-0)] text-[var(--color-text-primary)] flex items-center justify-center p-6 select-none">
      <div className="glass max-w-md w-full rounded-2xl p-8 border border-[var(--color-border)] text-center space-y-4 shadow-2xl">
        <div className="w-14 h-14 rounded-2xl bg-[var(--color-high)]/15 border border-[var(--color-high)]/30 mx-auto flex items-center justify-center text-[var(--color-high)]">
          <ClockIcon className="w-8 h-8" />
        </div>
        <h1 className="text-xl font-bold text-[var(--color-text-primary)]">Security Session Expired</h1>
        <p className="text-xs text-[var(--color-text-secondary)] leading-relaxed">
          Your JWT security token has expired due to inactivity. Re-authenticate your session to maintain encrypted telemetry stream access.
        </p>
        <Link
          to="/login"
          className="inline-block w-full py-3 rounded-xl bg-[var(--color-primary-500)] text-[var(--color-surface-0)] font-bold text-xs shadow-lg hover:opacity-90 transition-all"
        >
          Re-Authenticate Session →
        </Link>
      </div>
    </div>
  );
}
