import { Component, type ErrorInfo, type ReactNode } from "react";
import { ExclamationTriangleIcon, ArrowPathIcon } from "@heroicons/react/24/outline";

interface Props {
  children: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

export default class ErrorBoundary extends Component<Props, State> {
  public state: State = {
    hasError: false,
    error: null,
  };

  public static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error("SentinelX Uncaught Error Boundary:", error, errorInfo);
  }

  private handleReload = () => {
    window.location.reload();
  };

  private handleReset = () => {
    this.setState({ hasError: false, error: null });
  };

  public render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen bg-[#0a0e17] text-[#e2e8f0] flex flex-col items-center justify-center p-6 font-sans">
          <div className="max-w-md w-full bg-[#111827] border border-[#1e293b] rounded-2xl p-8 shadow-2xl text-center">
            <div className="w-16 h-16 rounded-2xl bg-red-500/10 border border-red-500/20 flex items-center justify-center mx-auto mb-6">
              <ExclamationTriangleIcon className="w-9 h-9 text-red-400" />
            </div>

            <h1 className="text-xl font-bold text-white mb-2">
              SOC Module Execution Exception
            </h1>

            <p className="text-xs text-[#94a3b8] mb-6 leading-relaxed">
              SentinelX encountered an unhandled runtime error rendering this view.
              Your security session remains active.
            </p>

            {this.state.error?.message && (
              <div className="bg-[#0f172a] border border-[#1e293b] rounded-lg p-3 text-left mb-6 font-mono text-[11px] text-red-300 break-words max-h-28 overflow-y-auto">
                {this.state.error.message}
              </div>
            )}

            <div className="flex gap-3">
              <button
                onClick={this.handleReset}
                className="flex-1 px-4 py-2.5 rounded-lg bg-[#1e293b] hover:bg-[#334155] text-white text-xs font-semibold transition-all duration-150"
              >
                Try Again
              </button>
              <button
                onClick={this.handleReload}
                className="flex-1 px-4 py-2.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 text-xs font-bold transition-all duration-150 flex items-center justify-center gap-2"
              >
                <ArrowPathIcon className="w-4 h-4" />
                Reload SOC
              </button>
            </div>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
