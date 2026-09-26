"use client";

import { useEffect, useState } from "react";
import {
  Activity,
  Swords,
  Shield,
  ScrollText,
  FileText,
  Settings as SettingsIcon,
  Radar,
  ShieldCheck,
  Command as CommandIcon,
  BookOpen,
  Keyboard,
  FlaskConical,
  Bell,
  BellRing,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { useAppStore } from "@/lib/store";
import { useMonitorWs } from "@/hooks/use-monitor-ws";
import { useKeyboardShortcuts } from "@/hooks/use-keyboard-shortcuts";
import { useBrowserNotifications } from "@/hooks/use-browser-notifications";
import { AuthWarning } from "@/components/soc/auth-warning";
import { StatusDot } from "@/components/soc/status-dot";
import { CommandPalette } from "@/components/soc/command-palette";
import { DetectionRulesDialog } from "@/components/soc/detection-rules-dialog";
import { KeyboardShortcutsDialog } from "@/components/soc/keyboard-shortcuts-dialog";
import { CustomRulesManager } from "@/components/soc/custom-rules-manager";
import { LiveMonitorView } from "@/components/views/live-monitor-view";
import { OffenseView } from "@/components/views/offense-view";
import { DefenseView } from "@/components/views/defense-view";
import { HistoryView } from "@/components/views/history-view";
import { ReportsView } from "@/components/views/reports-view";
import { SettingsView } from "@/components/views/settings-view";
import { useSettingsLoader } from "@/hooks/use-settings-loader";
import { toast } from "sonner";

interface NavItem {
  key: "monitor" | "offense" | "defense" | "history" | "reports" | "settings";
  label: string;
  icon: typeof Activity;
  accent?: string;
}

const NAV: NavItem[] = [
  { key: "monitor", label: "Live Monitor", icon: Activity },
  { key: "offense", label: "Offense", icon: Swords, accent: "var(--soc-critical)" },
  { key: "defense", label: "Defense", icon: Shield, accent: "var(--soc-low)" },
  { key: "history", label: "History", icon: ScrollText },
  { key: "reports", label: "Reports", icon: FileText },
  { key: "settings", label: "Settings", icon: SettingsIcon },
];

export default function Home() {
  const view = useAppStore((s) => s.view);
  const setView = useAppStore((s) => s.setView);
  const sessionId = useAppStore((s) => s.sessionId);
  const status = useAppStore((s) => s.status);
  const connected = useAppStore((s) => s.connected);
  const mode = useAppStore((s) => s.mode);
  const [rulesOpen, setRulesOpen] = useState(false);
  const [customRulesOpen, setCustomRulesOpen] = useState(false);

  // Connect websocket whenever there's an active session
  useMonitorWs({ sessionId, enabled: !!sessionId });

  // Load settings on mount
  useSettingsLoader();

  // Browser notifications for high-severity alerts (when tab is in background)
  const notif = useBrowserNotifications();

  // Global keyboard shortcuts
  const { showHelp, setShowHelp } = useKeyboardShortcuts({
    onViewChange: (v) => setView(v),
    getCurrentView: () => view,
    onEventNavigate: (dir) => {
      const s = useAppStore.getState();
      if (!s.events.length) return;
      const currentIdx = s.selectedEventId
        ? s.events.findIndex((e) => e.eventId === s.selectedEventId)
        : -1;
      let nextIdx: number;
      if (currentIdx === -1) {
        nextIdx = 0;
      } else if (dir === "next") {
        nextIdx = Math.min(s.events.length - 1, currentIdx + 1);
      } else {
        nextIdx = Math.max(0, currentIdx - 1);
      }
      const next = s.events[nextIdx];
      if (next) {
        s.setSelectedEvent(next.eventId);
        toast.info(`Event ${nextIdx + 1}/${s.events.length}: ${next.eventId}`, { duration: 1500 });
      }
    },
    onAlertAck: () => {
      const s = useAppStore.getState();
      // Find first active alert
      const alert = s.alerts.find((a) => a.status === "active");
      if (!alert || !s.sessionId) {
        toast.info("No active alert to acknowledge");
        return;
      }
      import("@/lib/api-client").then(({ api }) => {
        api.updateAlertStatus(s.sessionId!, alert.alertId, "acknowledged").then(() => {
          s.updateAlertStatus(alert.alertId, "acknowledged");
          toast.success("Alert acknowledged (A)");
        }).catch(() => toast.error("Failed to acknowledge alert"));
      });
    },
    onAlertResolve: () => {
      const s = useAppStore.getState();
      const alert = s.alerts.find((a) => a.status !== "resolved");
      if (!alert || !s.sessionId) {
        toast.info("No alert to resolve");
        return;
      }
      import("@/lib/api-client").then(({ api }) => {
        api.updateAlertStatus(s.sessionId!, alert.alertId, "resolved").then(() => {
          s.updateAlertStatus(alert.alertId, "resolved");
          toast.success("Alert resolved (R)");
        }).catch(() => toast.error("Failed to resolve alert"));
      });
    },
    onPauseToggle: () => {
      const s = useAppStore.getState();
      s.setPaused(!s.paused);
      toast.info(s.paused ? "Stream resumed" : "Stream paused", { duration: 1200 });
    },
    onClearView: () => {
      useAppStore.getState().clearLiveView();
      toast.success("Live view cleared (C)");
    },
    onExportEvents: () => {
      const s = useAppStore.getState();
      if (!s.events.length) {
        toast.info("No events to export");
        return;
      }
      import("@/lib/export-utils").then(({ exportEventsCsv }) => {
        exportEventsCsv(s.events.slice(0, 500), s.targetAddress || "live");
        toast.success("Events exported (E)");
      });
    },
  });

  // Periodic health check for "system online" indicator
  useEffect(() => {
    let alive = true;
    const check = async () => {
      try {
        const res = await fetch("/api/health");
        if (!alive) return;
        if (!res.ok) toast.error("Backend health check failed");
      } catch {
        /* ignore */
      }
    };
    check();
    const id = setInterval(check, 30000);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, []);

  const monitorActive = status === "monitoring" || status === "scanning" || status === "initializing";

  return (
    <div className="flex h-screen min-h-0 w-full overflow-hidden bg-background text-foreground soc-grid-bg">
      {/* Sidebar */}
      <aside className="flex w-[200px] shrink-0 flex-col border-r border-sidebar-border bg-sidebar/80 backdrop-blur-md">
        {/* Brand */}
        <div className="flex items-center gap-2.5 border-b border-sidebar-border px-4 py-3.5">
          <div className="radar-sweep relative flex h-8 w-8 items-center justify-center rounded-md bg-gradient-to-br from-[color:var(--soc-low)] to-[color:var(--soc-info)]">
            <Radar className="relative h-4.5 w-4.5 text-white" />
          </div>
          <div className="min-w-0">
            <div className="font-mono-data text-sm font-bold tracking-tight leading-none">
              LiveSOC
            </div>
            <div className="mt-0.5 text-[9px] uppercase tracking-wider text-muted-foreground">
              Security Monitor
            </div>
          </div>
        </div>

        {/* Nav */}
        <nav className="flex-1 overflow-y-auto px-2 py-3 soc-scrollbar">
          <div className="mb-1 px-2 font-mono-data text-[9px] uppercase tracking-wider text-muted-foreground/70">
            Operations
          </div>
          <ul className="space-y-0.5">
            {NAV.map((item) => {
              const active = view === item.key;
              const Icon = item.icon;
              const accentColor = item.accent ?? "var(--sidebar-primary)";
              return (
                <li key={item.key}>
                  <button
                    onClick={() => setView(item.key)}
                    className={cn(
                      "group relative flex w-full items-center gap-2.5 rounded-md px-2.5 py-2 pl-3 text-left text-sm transition-all duration-150",
                      active
                        ? "bg-sidebar-accent text-sidebar-accent-foreground shadow-sm"
                        : "text-sidebar-foreground/70 hover:bg-sidebar-accent/50 hover:text-sidebar-accent-foreground hover:translate-x-0.5",
                    )}
                    style={
                      active
                        ? {
                            backgroundImage:
                              "linear-gradient(90deg, color-mix(in oklch, var(--sidebar-accent) 100%, transparent), color-mix(in oklch, var(--sidebar-accent) 60%, transparent))",
                          }
                        : undefined
                    }
                  >
                    {/* Left accent bar — 3px, accent color, brightens on hover */}
                    <span
                      aria-hidden="true"
                      className={cn(
                        "absolute left-0 top-1/2 h-5 -translate-y-1/2 rounded-r-sm transition-all duration-150",
                        active ? "opacity-100 w-[3px]" : "opacity-0 w-[2px] group-hover:opacity-40",
                      )}
                      style={{
                        backgroundColor: accentColor,
                        boxShadow: active
                          ? `0 0 8px -1px ${accentColor}, 0 0 2px ${accentColor}`
                          : "none",
                      }}
                    />
                    <Icon
                      className={cn(
                        "h-4 w-4 shrink-0 transition-colors",
                        active ? "text-foreground" : "text-muted-foreground group-hover:text-foreground",
                      )}
                      style={active && item.accent ? { color: item.accent } : undefined}
                    />
                    <span className="truncate font-medium">{item.label}</span>
                    {/* Bottom border glow on active */}
                    {active && (
                      <span
                        aria-hidden="true"
                        className="pointer-events-none absolute inset-x-1 bottom-0 h-px"
                        style={{
                          background: `linear-gradient(90deg, transparent, ${accentColor}, transparent)`,
                          opacity: 0.6,
                        }}
                      />
                    )}
                  </button>
                </li>
              );
            })}
          </ul>
        </nav>

        {/* Connection status */}
        <div className="border-t border-sidebar-border px-3 py-2.5">
          <div
            className={cn(
              "relative overflow-hidden rounded-md bg-sidebar-accent/40 p-2.5",
              monitorActive && "scanline",
            )}
          >
            <div className="mb-1.5 flex items-center justify-between">
              <span className="font-mono-data text-[9px] uppercase tracking-wider text-muted-foreground">
                System
              </span>
              <StatusDot
                status="online"
                pulse
                label="ONLINE"
                className="text-[9px]"
              />
            </div>
            {sessionId && (
              <div className="mb-1.5 flex items-center justify-between">
                <span className="font-mono-data text-[9px] uppercase tracking-wider text-muted-foreground">
                  Monitor
                </span>
                <StatusDot
                  status={monitorActive ? "monitoring" : status}
                  pulse={monitorActive}
                  label={monitorActive ? "ACTIVE" : status.toUpperCase()}
                  className="text-[9px]"
                />
              </div>
            )}
            {sessionId && (
              <div className="flex items-center justify-between">
                <span className="font-mono-data text-[9px] uppercase tracking-wider text-muted-foreground">
                  Socket
                </span>
                <StatusDot
                  status={connected ? "connected" : "disconnected"}
                  pulse={connected}
                  label={connected ? "LIVE" : "RECONNECTING"}
                  className="text-[9px]"
                />
              </div>
            )}
          </div>
        </div>

        {/* Authorized scope warning */}
        <div className="border-t border-sidebar-border px-3 py-2">
          <AuthWarning />
          <div className="mt-1.5 px-1 text-[9px] font-mono-data tracking-wider text-muted-foreground/60">
            v1.0 · Authorized Lab Use Only
          </div>
        </div>
      </aside>

      {/* Main */}
      <main className="flex min-w-0 flex-1 flex-col overflow-hidden">
        {/* Top bar */}
        <header className="flex h-12 shrink-0 items-center justify-between border-b border-border/60 bg-card/40 px-4 backdrop-blur-md">
          <div className="flex items-center gap-3">
            <h1 className="font-mono-data text-sm font-semibold uppercase tracking-wider">
              {NAV.find((n) => n.key === view)?.label}
            </h1>
            {mode === "demo" && (
              <span className="rounded-sm border border-[color:var(--soc-medium)]/40 bg-[color:var(--soc-medium)]/10 px-1.5 py-0.5 font-mono-data text-[9px] font-bold uppercase tracking-wider text-[color:var(--soc-medium)]">
                Demo Mode
              </span>
            )}
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={() => setRulesOpen(true)}
              className="flex items-center gap-1.5 rounded-md border border-border/60 bg-card/40 px-2 py-1 font-mono-data text-[10px] uppercase tracking-wider text-muted-foreground transition-colors hover:bg-card/60 hover:text-foreground"
              title="View built-in detection rules reference"
            >
              <BookOpen className="h-3 w-3" />
              <span className="hidden sm:inline">Built-in Rules</span>
            </button>
            <button
              onClick={() => setCustomRulesOpen(true)}
              className="flex items-center gap-1.5 rounded-md border border-[color:var(--soc-medium)]/40 bg-[color:var(--soc-medium)]/10 px-2 py-1 font-mono-data text-[10px] uppercase tracking-wider text-[color:var(--soc-medium)] transition-colors hover:bg-[color:var(--soc-medium)]/20"
              title="Create and manage custom detection rules"
            >
              <FlaskConical className="h-3 w-3" />
              <span className="hidden sm:inline">Custom Rules</span>
            </button>
            <button
              onClick={() => setShowHelp(true)}
              className="flex items-center gap-1.5 rounded-md border border-border/60 bg-card/40 px-2 py-1 font-mono-data text-[10px] uppercase tracking-wider text-muted-foreground transition-colors hover:bg-card/60 hover:text-foreground"
              title="Show keyboard shortcuts (?)"
            >
              <Keyboard className="h-3 w-3" />
              <span className="hidden sm:inline">Shortcuts</span>
            </button>
            {notif.supported && (
              <button
                onClick={notif.requestPermission}
                className={cn(
                  "flex items-center gap-1.5 rounded-md border px-2 py-1 font-mono-data text-[10px] uppercase tracking-wider transition-colors",
                  notif.permission === "granted"
                    ? "border-[color:var(--soc-success)]/40 bg-[color:var(--soc-success)]/10 text-[color:var(--soc-success)] hover:bg-[color:var(--soc-success)]/20"
                    : "border-border/60 bg-card/40 text-muted-foreground hover:bg-card/60 hover:text-foreground",
                )}
                title={
                  notif.permission === "granted"
                    ? "Browser notifications enabled (fires on high/critical alerts when tab is in background)"
                    : "Enable browser notifications for high-severity alerts"
                }
              >
                {notif.permission === "granted" ? (
                  <BellRing className="h-3 w-3" />
                ) : (
                  <Bell className="h-3 w-3" />
                )}
                <span className="hidden sm:inline">
                  {notif.permission === "granted" ? "Notify On" : "Notify"}
                </span>
              </button>
            )}
            <button
              onClick={() => {
                // Trigger Cmd+K by dispatching a synthetic keyboard event
                document.dispatchEvent(
                  new KeyboardEvent("keydown", {
                    key: "k",
                    metaKey: true,
                    bubbles: true,
                  }),
                );
              }}
              className="flex items-center gap-1.5 rounded-md border border-border/60 bg-card/40 px-2 py-1 font-mono-data text-[10px] uppercase tracking-wider text-muted-foreground transition-colors hover:bg-card/60 hover:text-foreground"
              title="Open command palette (Cmd+K)"
            >
              <CommandIcon className="h-3 w-3" />
              <span className="hidden sm:inline">Cmd+K</span>
            </button>
            {sessionId && (
              <div className="flex items-center gap-2 font-mono-data text-[10px] text-muted-foreground">
                <ShieldCheck className="h-3.5 w-3.5 text-[color:var(--soc-success)]" />
                <span className="hidden md:inline">Authorized Lab Scope</span>
              </div>
            )}
          </div>
        </header>

        {/* View */}
        <div className="min-h-0 flex-1 overflow-hidden">
          {view === "monitor" && <LiveMonitorView />}
          {view === "offense" && <OffenseView />}
          {view === "defense" && <DefenseView />}
          {view === "history" && <HistoryView />}
          {view === "reports" && <ReportsView />}
          {view === "settings" && <SettingsView />}
        </div>
      </main>

      {/* Global overlays */}
      <CommandPalette onOpenRules={() => setRulesOpen(true)} />
      <DetectionRulesDialog open={rulesOpen} onOpenChange={setRulesOpen} />
      <KeyboardShortcutsDialog open={showHelp} onOpenChange={setShowHelp} />
      <CustomRulesManager open={customRulesOpen} onOpenChange={setCustomRulesOpen} />
    </div>
  );
}
