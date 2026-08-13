/**
 * SentinelX AI – Alert Toast Notification Component (Phase 6.4)
 * Renders non-blocking toast notifications for HIGH/CRITICAL real-time security alerts.
 * Auto-dismisses after 8 seconds. Maximum 5 concurrent toasts.
 */

import { useEffect, useRef } from "react";
import {
  ShieldExclamationIcon,
  XMarkIcon,
  ArrowTopRightOnSquareIcon,
} from "@heroicons/react/24/outline";
import { Link } from "react-router-dom";
import { useAlertStore, type ToastNotification } from "../../stores/alertStore";

const SEVERITY_BG: Record<string, string> = {
  CRITICAL: "from-red-950/90 to-red-900/80 border-red-500/60",
  HIGH:     "from-orange-950/90 to-orange-900/80 border-orange-500/60",
  MEDIUM:   "from-yellow-950/90 to-yellow-900/80 border-yellow-500/60",
  LOW:      "from-slate-900/90 to-slate-800/80 border-slate-500/60",
};
const SEVERITY_ICON: Record<string, string> = {
  CRITICAL: "text-red-400",
  HIGH:     "text-orange-400",
  MEDIUM:   "text-yellow-400",
  LOW:      "text-slate-400",
};
const SEVERITY_BADGE: Record<string, string> = {
  CRITICAL: "bg-red-500/20 text-red-400 ring-red-500/40",
  HIGH:     "bg-orange-500/20 text-orange-400 ring-orange-500/40",
  MEDIUM:   "bg-yellow-500/20 text-yellow-400 ring-yellow-500/40",
  LOW:      "bg-slate-500/20 text-slate-400 ring-slate-500/40",
};

const AUTO_DISMISS_MS = 8000;

interface SingleToastProps {
  notification: ToastNotification;
}

function SingleToast({ notification }: SingleToastProps) {
  const { dismissNotification } = useAlertStore();
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    timerRef.current = setTimeout(() => {
      dismissNotification(notification.id);
    }, AUTO_DISMISS_MS);
    return () => {
      if (timerRef.current) clearTimeout(timerRef.current);
    };
  }, [notification.id, dismissNotification]);

  const bg = SEVERITY_BG[notification.severity] ?? SEVERITY_BG.LOW;
  const iconColor = SEVERITY_ICON[notification.severity] ?? SEVERITY_ICON.LOW;
  const badge = SEVERITY_BADGE[notification.severity] ?? SEVERITY_BADGE.LOW;

  return (
    <div
      className={`
        relative flex items-start gap-3 p-3.5 rounded-xl border
        bg-gradient-to-br ${bg}
        shadow-2xl backdrop-blur-sm
        animate-slide-in-right
        max-w-sm w-full
      `}
      role="alert"
      aria-live="assertive"
    >
      {/* Severity Icon */}
      <ShieldExclamationIcon className={`w-5 h-5 mt-0.5 shrink-0 ${iconColor}`} />

      {/* Content */}
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 mb-0.5">
          <span
            className={`px-1.5 py-0.5 rounded text-[9px] font-extrabold tracking-wider uppercase font-mono ring-1 ${badge}`}
          >
            {notification.severity}
          </span>
          <span className="text-[10px] text-slate-400 font-mono">ALERT</span>
        </div>
        <p className="text-[11px] font-bold text-white leading-snug line-clamp-2">
          {notification.title}
        </p>
        {notification.hostname && (
          <p className="text-[10px] text-slate-400 font-mono mt-0.5 truncate">
            Host: {notification.hostname}
          </p>
        )}
      </div>

      {/* Actions */}
      <div className="flex flex-col items-end gap-1.5 shrink-0">
        <button
          onClick={() => dismissNotification(notification.id)}
          className="text-slate-500 hover:text-slate-300 transition-colors"
          aria-label="Dismiss alert notification"
        >
          <XMarkIcon className="w-3.5 h-3.5" />
        </button>
        <Link
          to={`/alerts`}
          onClick={() => dismissNotification(notification.id)}
          className="flex items-center gap-0.5 text-[9px] font-bold text-blue-400 hover:text-blue-300 transition-colors uppercase font-mono"
        >
          View
          <ArrowTopRightOnSquareIcon className="w-2.5 h-2.5" />
        </Link>
      </div>

      {/* Progress bar (auto-dismiss countdown) */}
      <div className="absolute bottom-0 left-0 right-0 h-0.5 rounded-b-xl bg-white/10">
        <div
          className="h-full rounded-b-xl bg-white/30"
          style={{
            animation: `shrink-progress ${AUTO_DISMISS_MS}ms linear forwards`,
          }}
        />
      </div>
    </div>
  );
}


/**
 * AlertToastContainer – renders all active toast notifications.
 * Place this once at the app root (inside Layout or App.tsx).
 */
export default function AlertToastContainer() {
  const { notifications, clearExpiredNotifications } = useAlertStore();

  // Periodically clean up dismissed notifications
  useEffect(() => {
    const interval = setInterval(clearExpiredNotifications, 2000);
    return () => clearInterval(interval);
  }, [clearExpiredNotifications]);

  const active = notifications.filter((n) => !n.dismissedAt);

  if (active.length === 0) return null;

  return (
    <div
      className="fixed top-4 right-4 z-[9999] flex flex-col gap-2 items-end pointer-events-none"
      aria-label="Security alert notifications"
    >
      {active.slice(0, 5).map((n) => (
        <div key={n.id} className="pointer-events-auto">
          <SingleToast notification={n} />
        </div>
      ))}

      <style>{`
        @keyframes slide-in-right {
          from { opacity: 0; transform: translateX(100%); }
          to   { opacity: 1; transform: translateX(0); }
        }
        @keyframes shrink-progress {
          from { width: 100%; }
          to   { width: 0%; }
        }
        .animate-slide-in-right {
          animation: slide-in-right 0.3s cubic-bezier(0.16, 1, 0.3, 1);
        }
      `}</style>
    </div>
  );
}
