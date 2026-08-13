/**
 * SentinelX AI – useRealtimeSOC React Hook (Phase 6.4)
 * Establishes an authenticated WebSocket connection to receive live SOC events.
 * Reconnects automatically with exponential backoff.
 */

import { useEffect, useRef, useCallback } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { useAlertStore } from "../stores/alertStore";
import type {
  RealtimeEvent,
  AlertCreatedPayload,
  SecurityAlertSummary,
  TelemetryReceivedPayload,
} from "../types/alert";

// Backend WebSocket URL (resolved at runtime)
function buildWsUrl(token: string): string {
  const apiBase =
    import.meta.env.VITE_API_URL || "https://sentinelx-2qer.onrender.com";
  const wsBase = apiBase.replace(/^https?:\/\//, "").replace(/\/$/, "");
  const protocol = apiBase.startsWith("https") ? "wss" : "ws";
  return `${protocol}://${wsBase}/api/v1/realtime/ws?token=${encodeURIComponent(token)}`;
}

// JWT storage key (matches AuthContext)
const TOKEN_KEY = "sentinelx_access_token";

// Backoff settings
const INITIAL_BACKOFF_MS = 1000;
const MAX_BACKOFF_MS = 30000;
const BACKOFF_MULTIPLIER = 2;

// Severity filter for toast notifications
const CRITICAL_SEVERITIES = new Set(["CRITICAL", "HIGH"]);

export interface RealtimeSOCState {
  connected: boolean;
  reconnecting: boolean;
  lastEvent: RealtimeEvent | null;
}

export function useRealtimeSOC(enabled: boolean = true): RealtimeSOCState {
  const queryClient = useQueryClient();
  const {
    addAlert,
    updateAlert,
    addTelemetryEvent,
    addNotification,
    setWsConnected,
    setWsReconnecting,
    wsConnected,
    wsReconnecting,
  } = useAlertStore();

  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const backoffRef = useRef<number>(INITIAL_BACKOFF_MS);
  const mountedRef = useRef<boolean>(true);
  const lastEventRef = useRef<RealtimeEvent | null>(null);

  const connect = useCallback(() => {
    if (!mountedRef.current || !enabled) return;

    const token = localStorage.getItem(TOKEN_KEY);
    if (!token) {
      // Not authenticated – do not attempt connection
      return;
    }

    const url = buildWsUrl(token);

    try {
      const ws = new WebSocket(url);
      wsRef.current = ws;
      setWsReconnecting(true);

      ws.onopen = () => {
        if (!mountedRef.current) {
          ws.close();
          return;
        }
        backoffRef.current = INITIAL_BACKOFF_MS;
        setWsConnected(true);
        setWsReconnecting(false);
      };

      ws.onmessage = (event: MessageEvent) => {
        if (!mountedRef.current) return;
        try {
          const msg: RealtimeEvent = JSON.parse(event.data as string);
          lastEventRef.current = msg;

          handleEvent(msg);
        } catch {
          // Ignore malformed messages
        }
      };

      ws.onerror = () => {
        // onclose will handle reconnection
      };

      ws.onclose = (event) => {
        wsRef.current = null;
        setWsConnected(false);

        // Close codes 4001/4003 = auth failure, do not reconnect
        if (event.code === 4001 || event.code === 4003) {
          setWsReconnecting(false);
          return;
        }

        if (!mountedRef.current) return;

        // Exponential backoff reconnect
        const delay = Math.min(backoffRef.current, MAX_BACKOFF_MS);
        backoffRef.current = Math.min(backoffRef.current * BACKOFF_MULTIPLIER, MAX_BACKOFF_MS);

        setWsReconnecting(true);
        reconnectTimerRef.current = setTimeout(() => {
          if (mountedRef.current) connect();
        }, delay);
      };
    } catch {
      // WebSocket constructor threw (invalid URL, etc.)
      setWsReconnecting(false);
    }
  }, [enabled, addAlert, updateAlert, addTelemetryEvent, addNotification, setWsConnected, setWsReconnecting, queryClient]);

  // ── Event Handler ───────────────────────────────────────────────────────────

  function handleEvent(msg: RealtimeEvent): void {
    switch (msg.event) {
      case "alert.created": {
        const payload = msg.payload as unknown as AlertCreatedPayload;
        const summary: SecurityAlertSummary = {
          id: payload.id,
          alert_id: payload.alert_id,
          title: payload.title,
          alert_type: payload.alert_type,
          severity: payload.severity,
          status: payload.status,
          source: payload.source,
          agent_id: payload.agent_id,
          hostname: payload.hostname,
          mitre_tactic: payload.mitre_tactic,
          mitre_technique: payload.mitre_technique,
          detected_at: payload.detected_at,
          updated_at: msg.timestamp,
          occurrence_count: payload.occurrence_count ?? 1,
        };
        addAlert(summary);

        // Show toast for HIGH/CRITICAL
        if (CRITICAL_SEVERITIES.has(payload.severity)) {
          addNotification({
            id: `notif-${payload.id}-${Date.now()}`,
            alertId: payload.id,
            title: payload.title,
            severity: payload.severity,
            hostname: payload.hostname,
            detectedAt: payload.detected_at,
          });
        }

        // Invalidate queries so REST-based components refresh
        void queryClient.invalidateQueries({ queryKey: ["alert-statistics"] });
        void queryClient.invalidateQueries({ queryKey: ["recent-alerts"] });
        break;
      }

      case "alert.updated":
      case "alert.acknowledged":
      case "alert.investigated":
      case "alert.resolved":
      case "alert.dismissed": {
        const payload = msg.payload as unknown as AlertCreatedPayload;
        if (payload.id) {
          updateAlert({
            id: payload.id,
            alert_id: payload.alert_id ?? "",
            title: payload.title ?? "",
            alert_type: payload.alert_type ?? "unknown",
            severity: payload.severity ?? "LOW",
            status: payload.status ?? "NEW",
            source: payload.source ?? null,
            agent_id: payload.agent_id ?? null,
            hostname: payload.hostname ?? null,
            mitre_tactic: payload.mitre_tactic ?? null,
            mitre_technique: payload.mitre_technique ?? null,
            detected_at: payload.detected_at ?? msg.timestamp,
            updated_at: msg.timestamp,
            occurrence_count: payload.occurrence_count ?? 1,
          });
        }
        void queryClient.invalidateQueries({ queryKey: ["alert-statistics"] });
        void queryClient.invalidateQueries({ queryKey: ["alerts"] });
        break;
      }

      case "telemetry.received": {
        const payload = msg.payload as unknown as TelemetryReceivedPayload;
        addTelemetryEvent(payload.event_count ?? 1);
        break;
      }

      case "endpoint.status_changed":
      case "endpoint.online":
      case "endpoint.offline": {
        void queryClient.invalidateQueries({ queryKey: ["agent-statistics"] });
        void queryClient.invalidateQueries({ queryKey: ["agents"] });
        break;
      }

      case "threat.detected": {
        void queryClient.invalidateQueries({ queryKey: ["threats"] });
        void queryClient.invalidateQueries({ queryKey: ["dashboard-summary"] });
        break;
      }

      case "ping": {
        // Respond with pong
        if (wsRef.current?.readyState === WebSocket.OPEN) {
          wsRef.current.send(JSON.stringify({ event: "pong" }));
        }
        break;
      }

      case "connection.established":
        break;

      default:
        break;
    }
  }

  useEffect(() => {
    mountedRef.current = true;
    if (enabled) {
      connect();
    }

    return () => {
      mountedRef.current = false;
      if (reconnectTimerRef.current) clearTimeout(reconnectTimerRef.current);
      if (wsRef.current) {
        wsRef.current.close(1000, "Component unmounted");
        wsRef.current = null;
      }
    };
  }, [enabled, connect]);

  return {
    connected: wsConnected,
    reconnecting: wsReconnecting,
    lastEvent: lastEventRef.current,
  };
}
