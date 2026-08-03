import { Link } from "react-router-dom";
import { ShieldExclamationIcon } from "@heroicons/react/24/outline";

export default function UnauthorizedPage() {
  return (
    <div className="min-h-screen bg-[var(--color-surface-0)] text-[var(--color-text-primary)] flex items-center justify-center p-6 select-none">
      <div className="glass max-w-md w-full rounded-2xl p-8 border border-[var(--color-critical)]/30 text-center space-y-4 shadow-2xl">
        <div className="w-14 h-14 rounded-2xl bg-[var(--color-critical)]/15 border border-[var(--color-critical)]/30 mx-auto flex items-center justify-center text-[var(--color-critical)]">
          <ShieldExclamationIcon className="w-8 h-8" />
        </div>
        <h1 className="text-xl font-bold text-[var(--color-text-primary)]">403 – Unauthorized Access</h1>
        <p className="text-xs text-[var(--color-text-secondary)] leading-relaxed">
          Access Denied. Your assigned Role-Based Access Control (RBAC) permissions are insufficient for this operational SOC module.
        </p>
        <Link
          to="/"
          className="inline-block w-full py-3 rounded-xl bg-[var(--color-surface-300)] text-[var(--color-text-primary)] font-bold text-xs hover:bg-[var(--color-surface-400)] transition-all"
        >
          Return to Command Center Dashboard
        </Link>
      </div>
    </div>
  );
}
