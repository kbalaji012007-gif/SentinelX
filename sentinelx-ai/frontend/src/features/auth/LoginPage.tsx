import { useState, type FormEvent } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import {
  ShieldCheckIcon,
  LockClosedIcon,
  EnvelopeIcon,
  ExclamationCircleIcon,
  SparklesIcon,
  XMarkIcon,
} from "@heroicons/react/24/outline";
import { useAuth } from "../../contexts/AuthContext";

export default function LoginPage() {
  const navigate = useNavigate();
  const location = useLocation();
  const { login } = useAuth();

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [rememberMe, setRememberMe] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [showForgotModal, setShowForgotModal] = useState(false);
  const [forgotSubmitted, setForgotSubmitted] = useState(false);

  const from = (location.state as any)?.from?.pathname || "/";

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (!email || !password) {
      setError("Please fill in both Email and Password.");
      return;
    }

    setError(null);
    setIsSubmitting(true);

    try {
      await login(email, password, rememberMe);
      navigate(from, { replace: true });
    } catch (err: any) {
      setError(err.message || "Invalid authentication credentials.");
    } finally {
      setIsSubmitting(false);
    }
  };

  const fillDemoAnalyst = () => {
    setEmail("alex.rivera@sentinelx.ai");
    setPassword("Password123!");
    setError(null);
  };

  return (
    <div className="min-h-screen bg-[var(--color-surface-0)] text-[var(--color-text-primary)] flex items-center justify-center p-4 relative overflow-hidden select-none">
      {/* Background Cyber Glow Gradients */}
      <div className="absolute -top-40 -left-40 w-96 h-96 rounded-full bg-[var(--color-primary-500)]/10 blur-3xl pointer-events-none" />
      <div className="absolute -bottom-40 -right-40 w-96 h-96 rounded-full bg-[var(--color-secondary-500)]/10 blur-3xl pointer-events-none" />

      <div className="w-full max-w-md space-y-6 relative z-10">
        {/* Brand Logo & Header */}
        <div className="text-center space-y-2">
          <div className="inline-flex w-14 h-14 rounded-2xl bg-gradient-to-br from-[var(--color-primary-500)]/20 to-[var(--color-secondary-500)]/20 border border-[var(--color-primary-500)]/40 items-center justify-center shadow-[0_0_25px_rgba(0,229,255,0.2)] mb-2">
            <ShieldCheckIcon className="w-8 h-8 text-[var(--color-primary-500)]" />
          </div>
          <h1 className="text-2xl font-black tracking-tight text-[var(--color-text-primary)]">
            SentinelX AI
          </h1>
          <p className="text-xs font-semibold text-[var(--color-primary-500)] uppercase tracking-widest">
            Autonomous Security Operations Platform
          </p>
        </div>

        {/* Login Form Glass Card */}
        <div className="glass rounded-2xl p-8 border border-[var(--color-border)] shadow-2xl space-y-6">
          <div className="border-b border-[var(--color-border)] pb-3">
            <h2 className="text-base font-bold text-[var(--color-text-primary)]">Analyst Authentication</h2>
            <p className="text-xs text-[var(--color-text-muted)] mt-0.5">Enter your credentials to access the SOC Command Center</p>
          </div>

          {/* Quick Fill Demo Banner */}
          <div className="p-3 rounded-xl bg-[var(--color-surface-200)] border border-[var(--color-border)] flex items-center justify-between">
            <div className="flex items-center gap-2">
              <SparklesIcon className="w-4 h-4 text-[var(--color-secondary-500)]" />
              <span className="text-xs text-[var(--color-text-secondary)] font-medium">Demo Analyst Account</span>
            </div>
            <button
              onClick={fillDemoAnalyst}
              className="text-[10px] font-bold px-2.5 py-1 rounded bg-[var(--color-secondary-500)]/20 text-[var(--color-secondary-500)] hover:bg-[var(--color-secondary-500)]/30 transition-colors"
            >
              Auto-Fill Credentials
            </button>
          </div>

          {/* Error Callout Alert */}
          {error && (
            <div className="p-3 rounded-xl bg-[var(--color-critical)]/15 border border-[var(--color-critical)]/40 text-[var(--color-critical)] text-xs font-medium flex items-center gap-2 animate-fade-in">
              <ExclamationCircleIcon className="w-4 h-4 shrink-0" />
              <span>{error}</span>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            {/* Email Field */}
            <div className="space-y-1">
              <label className="block text-xs font-semibold text-[var(--color-text-muted)] uppercase tracking-wider">
                Analyst Email
              </label>
              <div className="relative">
                <EnvelopeIcon className="w-4 h-4 text-[var(--color-text-muted)] absolute left-3.5 top-1/2 -translate-y-1/2" />
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="analyst@sentinelx.ai"
                  className="w-full bg-[var(--color-surface-200)] text-xs font-mono text-[var(--color-text-primary)] placeholder-[var(--color-text-muted)] rounded-xl pl-10 pr-4 py-2.5 border border-[var(--color-border)] focus:outline-none focus:border-[var(--color-primary-500)] focus:ring-1 focus:ring-[var(--color-primary-500)] transition-all"
                  required
                />
              </div>
            </div>

            {/* Password Field */}
            <div className="space-y-1">
              <label className="block text-xs font-semibold text-[var(--color-text-muted)] uppercase tracking-wider">
                Password
              </label>
              <div className="relative">
                <LockClosedIcon className="w-4 h-4 text-[var(--color-text-muted)] absolute left-3.5 top-1/2 -translate-y-1/2" />
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••••••"
                  className="w-full bg-[var(--color-surface-200)] text-xs font-mono text-[var(--color-text-primary)] placeholder-[var(--color-text-muted)] rounded-xl pl-10 pr-4 py-2.5 border border-[var(--color-border)] focus:outline-none focus:border-[var(--color-primary-500)] focus:ring-1 focus:ring-[var(--color-primary-500)] transition-all"
                  required
                />
              </div>
            </div>

            {/* Remember Me & Forgot Password */}
            <div className="flex items-center justify-between text-xs pt-1">
              <label className="flex items-center gap-2 cursor-pointer text-[var(--color-text-secondary)]">
                <input
                  type="checkbox"
                  checked={rememberMe}
                  onChange={(e) => setRememberMe(e.target.checked)}
                  className="w-4 h-4 rounded bg-[var(--color-surface-200)] border-[var(--color-border)] accent-[var(--color-primary-500)]"
                />
                <span>Remember Me (30 Days)</span>
              </label>
              <button
                type="button"
                onClick={() => setShowForgotModal(true)}
                className="text-[var(--color-primary-500)] hover:underline font-medium"
              >
                Forgot Password?
              </button>
            </div>

            {/* Login Submit Button */}
            <button
              type="submit"
              disabled={isSubmitting}
              className="w-full py-3 rounded-xl bg-gradient-to-r from-[var(--color-primary-500)] to-[var(--color-primary-600)] text-[var(--color-surface-0)] font-bold text-xs shadow-lg shadow-[var(--color-primary-500)]/20 hover:opacity-95 transition-all disabled:opacity-50 flex items-center justify-center gap-2"
            >
              {isSubmitting ? (
                <>
                  <span className="w-4 h-4 border-2 border-black border-t-transparent rounded-full animate-spin" />
                  <span>Authenticating...</span>
                </>
              ) : (
                <span>Authenticate Session →</span>
              )}
            </button>
          </form>
        </div>

        {/* Footer */}
        <p className="text-center text-[11px] text-[var(--color-text-muted)] font-mono">
          SentinelX Security Engine v2.0 • Encrypted Connection
        </p>
      </div>

      {/* Forgot Password Modal */}
      {showForgotModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm animate-fade-in">
          <div className="w-full max-w-sm bg-[var(--color-surface-100)] rounded-2xl border border-[var(--color-border)] p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between pb-3 border-b border-[var(--color-border)]">
              <h3 className="text-sm font-bold text-[var(--color-text-primary)]">Password Reset Request</h3>
              <button onClick={() => setShowForgotModal(false)} className="p-1 text-[var(--color-text-muted)] hover:text-white">
                <XMarkIcon className="w-5 h-5" />
              </button>
            </div>

            {forgotSubmitted ? (
              <div className="space-y-3 text-center py-4">
                <p className="text-xs text-[var(--color-safe)] font-semibold">Reset instructions sent to registered email.</p>
                <button
                  onClick={() => {
                    setShowForgotModal(false);
                    setForgotSubmitted(false);
                  }}
                  className="px-4 py-2 bg-[var(--color-surface-300)] text-xs font-bold rounded-lg text-[var(--color-text-primary)]"
                >
                  Return to Login
                </button>
              </div>
            ) : (
              <div className="space-y-3 text-xs">
                <p className="text-[var(--color-text-secondary)]">Enter your registered SOC analyst email to receive a password reset token.</p>
                <input
                  type="email"
                  placeholder="analyst@sentinelx.ai"
                  className="w-full bg-[var(--color-surface-200)] px-3 py-2 rounded-lg border border-[var(--color-border)] text-[var(--color-text-primary)] font-mono"
                />
                <button
                  onClick={() => setForgotSubmitted(true)}
                  className="w-full py-2.5 rounded-lg bg-[var(--color-primary-500)] text-[var(--color-surface-0)] font-bold"
                >
                  Send Reset Token
                </button>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
