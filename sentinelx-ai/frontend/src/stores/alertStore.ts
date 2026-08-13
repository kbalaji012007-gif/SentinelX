/**
 * SentinelX AI – Alert Zustand Store (Phase 6.4)
 * Global real-time alert state for live feed, toast notifications, and telemetry counters.
 */

import { create } from "zustand";
import type { SecurityAlertSummary } from "../types/alert";

export interface ToastNotification {
  id: string;
  alertId: string;
  title: string;
  severity: string;
  hostname: string | null;
  detectedAt: string;
  dismissedAt?: number;
}

interface AlertStoreState {
  // Live alert feed (capped at 50 most recent)
  recentAlerts: SecurityAlertSummary[];
  // Unread count for nav badge
  unreadCount: number;

  // Live telemetry stats
  telemetryEventCount: number;
  eventsPerSecond: number;
  lastEventAt: string | null;

  // Toast notifications (HIGH/CRITICAL only)
  notifications: ToastNotification[];

  // WebSocket connection state
  wsConnected: boolean;
  wsReconnecting: boolean;

  // Actions
  addAlert: (alert: SecurityAlertSummary) => void;
  updateAlert: (alert: SecurityAlertSummary) => void;
  markAllRead: () => void;
  markAlertRead: (alertId: string) => void;
  setRecentAlerts: (alerts: SecurityAlertSummary[]) => void;

  // Telemetry tracking
  addTelemetryEvent: (eventCount: number) => void;
  resetTelemetryStats: () => void;

  // Notifications
  addNotification: (notification: ToastNotification) => void;
  dismissNotification: (notificationId: string) => void;
  clearExpiredNotifications: () => void;

  // WS state
  setWsConnected: (connected: boolean) => void;
  setWsReconnecting: (reconnecting: boolean) => void;
}

// Track EPS calculation
let _eventCountWindow: number[] = [];

export const useAlertStore = create<AlertStoreState>((set) => ({
  recentAlerts: [],
  unreadCount: 0,
  telemetryEventCount: 0,
  eventsPerSecond: 0,
  lastEventAt: null,
  notifications: [],
  wsConnected: false,
  wsReconnecting: false,

  // ── Alert Actions ──────────────────────────────────────────────────────────

  addAlert: (alert) => {
    set((state) => {
      // Prevent duplicates
      const exists = state.recentAlerts.find((a) => a.alert_id === alert.alert_id);
      if (exists) {
        return {
          recentAlerts: state.recentAlerts.map((a) =>
            a.alert_id === alert.alert_id ? { ...alert } : a
          ),
        };
      }
      const updated = [alert, ...state.recentAlerts].slice(0, 50);
      return {
        recentAlerts: updated,
        unreadCount: state.unreadCount + 1,
      };
    });
  },

  updateAlert: (alert) => {
    set((state) => ({
      recentAlerts: state.recentAlerts.map((a) =>
        a.alert_id === alert.alert_id ? { ...alert } : a
      ),
    }));
  },

  markAllRead: () => set({ unreadCount: 0 }),

  markAlertRead: (alertId) => {
    set((state) => {
      const alertExists = state.recentAlerts.find((a) => a.id === alertId);
      return {
        unreadCount: alertExists && state.unreadCount > 0
          ? state.unreadCount - 1
          : state.unreadCount,
      };
    });
  },

  setRecentAlerts: (alerts) =>
    set({ recentAlerts: alerts.slice(0, 50) }),

  // ── Telemetry Tracking ─────────────────────────────────────────────────────

  addTelemetryEvent: (eventCount) => {
    const now = Date.now();
    _eventCountWindow.push(now);

    // Keep only last 60 seconds of events for EPS calculation
    const cutoff = now - 60000;
    _eventCountWindow = _eventCountWindow.filter((t) => t > cutoff);
    const eps = Math.round(_eventCountWindow.length / 60);

    set((state) => ({
      telemetryEventCount: state.telemetryEventCount + eventCount,
      eventsPerSecond: eps,
      lastEventAt: new Date().toISOString(),
    }));
  },

  resetTelemetryStats: () => {
    _eventCountWindow = [];
    set({ telemetryEventCount: 0, eventsPerSecond: 0, lastEventAt: null });
  },

  // ── Notifications ──────────────────────────────────────────────────────────

  addNotification: (notification) => {
    set((state) => {
      // Throttle: max 1 notification per endpoint per 10 seconds
      const recentFromSameHost = state.notifications.find(
        (n) =>
          n.hostname === notification.hostname &&
          !n.dismissedAt &&
          Date.now() - new Date(n.detectedAt).getTime() < 10000
      );
      if (recentFromSameHost) return {};

      return {
        notifications: [notification, ...state.notifications].slice(0, 5),
      };
    });
  },

  dismissNotification: (notificationId) => {
    set((state) => ({
      notifications: state.notifications.map((n) =>
        n.id === notificationId ? { ...n, dismissedAt: Date.now() } : n
      ),
    }));
  },

  clearExpiredNotifications: () => {
    const NOTIFICATION_LIFETIME_MS = 8000;
    set((state) => ({
      notifications: state.notifications.filter(
        (n) => !n.dismissedAt || Date.now() - n.dismissedAt < NOTIFICATION_LIFETIME_MS
      ),
    }));
  },

  // ── WebSocket State ────────────────────────────────────────────────────────

  setWsConnected: (connected) => set({ wsConnected: connected, wsReconnecting: !connected ? false : undefined as unknown as boolean }),
  setWsReconnecting: (reconnecting) => set({ wsReconnecting: reconnecting }),
}));
