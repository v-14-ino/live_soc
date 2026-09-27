"use client";

import { useEffect, useRef, useCallback, useState } from "react";
import { useAppStore } from "@/lib/store";
import { toast } from "sonner";
import type { SecurityAlert } from "@/lib/types";

// ============================================================
// Browser Notifications Hook
//
// Requests notification permission and fires browser notifications
// when high or critical severity alerts arrive via the WebSocket.
// Shows a permission prompt banner on first high-severity alert.
//
// IMPORTANT: `supported` and `permission` return deterministic
// values ("unknown") during the initial render (SSR + client first
// paint) to avoid hydration mismatches. The actual browser state
// is read in a useEffect AFTER mount, then the state updates to
// trigger a re-render with the correct values.
// ============================================================

const NOTIFIED_ALERT_IDS = new Set<string>();
const MAX_NOTIFIED_TRACK = 200; // prevent unbounded growth

function trackNotified(alertId: string): void {
  NOTIFIED_ALERT_IDS.add(alertId);
  if (NOTIFIED_ALERT_IDS.size > MAX_NOTIFIED_TRACK) {
    // drop oldest ~50 entries
    const it = NOTIFIED_ALERT_IDS.values();
    for (let i = 0; i < 50; i++) it.next();
    for (let i = 0; i < 50; i++) {
      const v = it.next();
      if (v.done) break;
      NOTIFIED_ALERT_IDS.delete(v.value);
    }
  }
}

export function useBrowserNotifications() {
  const alerts = useAppStore((s) => s.alerts);
  const sessionId = useAppStore((s) => s.sessionId);
  const lastCheckedRef = useRef<number>(0);

  // Deterministic initial state for SSR + client first paint.
  // Updated to real browser values AFTER mount in useEffect.
  const [supported, setSupported] = useState(false);
  const [permission, setPermission] = useState<string>("unknown");

  // Read actual browser notification state after mount (client-only).
  // This is a deliberate post-mount state sync to avoid hydration mismatch:
  // SSR renders with supported=false/permission="unknown", then the client
  // updates to the real browser values after mount.
  useEffect(() => {
    if (typeof Notification === "undefined") {
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setSupported(false);
      setPermission("unsupported");
      return;
    }
    setSupported(true);
    setPermission(Notification.permission);
  }, []);

  const requestPermission = useCallback(async () => {
    if (typeof Notification === "undefined") {
      toast.info("Browser notifications are not supported in this environment.");
      return;
    }
    if (Notification.permission === "granted") {
      toast.success("Browser notifications are already enabled.");
      return;
    }
    if (Notification.permission === "denied") {
      toast.error("Browser notifications were blocked. Please enable them in your browser settings.");
      return;
    }
    const result = await Notification.requestPermission();
    // Update state so the button re-renders with the new permission.
    setPermission(result);
    if (result === "granted") {
      toast.success("Browser notifications enabled. You'll be alerted on high-severity events.");
    } else if (result === "denied") {
      toast.error("Browser notifications were blocked.");
    } else {
      toast.info("Browser notification permission dismissed.");
    }
  }, []);

  useEffect(() => {
    if (!sessionId) {
      lastCheckedRef.current = 0;
      return;
    }
    if (typeof Notification === "undefined") return;
    if (Notification.permission !== "granted") return;
    if (typeof document !== "undefined" && document.visibilityState === "visible") {
      // Only fire notifications when the tab is NOT visible (background)
      // When visible, the in-app alerts + toasts are sufficient.
      lastCheckedRef.current = alerts.length;
      return;
    }

    // Check for new high/critical alerts since last check
    const newAlerts = alerts.slice(0, Math.max(0, lastCheckedRef.current));
    lastCheckedRef.current = alerts.length;

    for (const alert of newAlerts) {
      if (alert.severity !== "high" && alert.severity !== "critical") continue;
      if (NOTIFIED_ALERT_IDS.has(alert.alertId)) continue;
      trackNotified(alert.alertId);

      try {
        const notif = new Notification(`LiveSOC — ${alert.severity.toUpperCase()} Alert`, {
          body: alert.ruleName + "\n" + alert.message,
          tag: alert.alertId,
          icon: "/logo.svg",
        });
        notif.onclick = () => {
          if (typeof window !== "undefined") window.focus();
          notif.close();
        };
        // Auto-close after 10 seconds
        setTimeout(() => notif.close(), 10000);
      } catch {
        // Notification API may fail in some browsers; ignore silently
      }
    }
  }, [alerts, sessionId]);

  return {
    supported,
    permission,
    requestPermission,
  };
}
