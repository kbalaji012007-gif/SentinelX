import { MagnifyingGlassIcon, BellIcon, SparklesIcon, ShieldCheckIcon, ArrowRightOnRectangleIcon } from "@heroicons/react/24/outline";
import { useAuth } from "../../contexts/AuthContext";

export default function Header() {
  const { user, logout } = useAuth();

  const userName = user ? `${user.first_name} ${user.last_name}`.trim() || user.email : "Analyst";
  const userRole = user?.role?.name || "SOC Analyst";
  const initials = user ? `${user.first_name?.[0] || ""}${user.last_name?.[0] || ""}` || "A" : "A";

  return (
    <header className="h-16 border-b border-[var(--color-border)] bg-[var(--color-surface-100)]/80 backdrop-blur-md sticky top-0 z-20 flex items-center justify-between px-6">
      {/* Global Search Bar */}
      <div className="flex items-center gap-3 w-96">
        <div className="relative w-full">
          <MagnifyingGlassIcon className="w-4 h-4 text-[var(--color-text-muted)] absolute left-3.5 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search IP, Hash, Hostname, CVE, or Query (Ctrl+K)..."
            className="w-full bg-[var(--color-surface-200)] text-xs text-[var(--color-text-primary)] placeholder-[var(--color-text-muted)] rounded-lg pl-9 pr-4 py-2 border border-[var(--color-border)] focus:outline-none focus:border-[var(--color-primary-500)] transition-colors"
          />
        </div>
      </div>

      {/* Right Controls */}
      <div className="flex items-center gap-4">
        {/* System Health Badge */}
        <div className="hidden md:flex items-center gap-2 px-3 py-1.5 rounded-full bg-[var(--color-surface-200)] border border-[var(--color-border)]">
          <ShieldCheckIcon className="w-4 h-4 text-[var(--color-safe)]" />
          <span className="text-xs font-medium text-[var(--color-text-secondary)]">All Systems Operational</span>
        </div>

        {/* AI Assistant Quick Trigger */}
        <button className="hidden sm:flex items-center gap-2 px-3 py-1.5 rounded-lg bg-[var(--color-secondary-500)]/15 border border-[var(--color-secondary-500)]/30 text-[var(--color-secondary-500)] hover:bg-[var(--color-secondary-500)]/25 text-xs font-semibold transition-all">
          <SparklesIcon className="w-4 h-4" />
          <span>Ask Gemini SOC</span>
        </button>

        {/* Notification Bell */}
        <button className="relative p-2 rounded-lg text-[var(--color-text-secondary)] hover:bg-[var(--color-surface-200)] hover:text-[var(--color-text-primary)] transition-colors">
          <BellIcon className="w-5 h-5" />
          <span className="absolute top-1.5 right-1.5 w-2 h-2 rounded-full bg-[var(--color-critical)] animate-pulse" />
        </button>

        {/* User Profile & Logout */}
        <div className="flex items-center gap-3 pl-3 border-l border-[var(--color-border)]">
          <div className="w-8 h-8 rounded-full bg-gradient-to-tr from-[var(--color-primary-500)] to-[var(--color-secondary-500)] p-[1px]">
            <div className="w-full h-full rounded-full bg-[var(--color-surface-100)] flex items-center justify-center text-xs font-bold text-[var(--color-primary-500)] font-mono">
              {initials}
            </div>
          </div>
          <div className="hidden lg:block text-left">
            <p className="text-xs font-semibold text-[var(--color-text-primary)] leading-none">
              {userName}
            </p>
            <p className="text-[10px] text-[var(--color-primary-500)] font-medium mt-0.5">
              {userRole}
            </p>
          </div>
          <button
            onClick={logout}
            title="Sign Out"
            className="p-1.5 rounded-lg text-[var(--color-text-muted)] hover:text-[var(--color-critical)] hover:bg-[var(--color-surface-200)] transition-colors ml-1"
          >
            <ArrowRightOnRectangleIcon className="w-5 h-5" />
          </button>
        </div>
      </div>
    </header>
  );
}
