"use client";

import { useEffect } from "react";
import {
  Activity,
  Swords,
  Shield,
  ScrollText,
  FileText,
  Settings as SettingsIcon,
  Radar,
  ShieldCheck,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { useAppStore } from "@/lib/store";
import { useMonitorWs } from "@/hooks/use-monitor-ws";
import { AuthWarning } from "@/components/soc/auth-warning";
import { StatusDot } from "@/components/soc/status-dot";
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

  // Connect websocket whenever there's an active session
  useMonitorWs({ sessionId, enabled: !!sessionId });

  // Load settings on mount
  useSettingsLoader();

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
          <div className="relative flex h-8 w-8 items-center justify-center rounded-md bg-gradient-to-br from-[color:var(--soc-low)] to-[color:var(--soc-info)]">
            <Radar className="h-4.5 w-4.5 text-white" />
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
              return (
                <li key={item.key}>
                  <button
                    onClick={() => setView(item.key)}
                    className={cn(
                      "group flex w-full items-center gap-2.5 rounded-md px-2.5 py-2 text-left text-sm transition-all",
                      active
                        ? "bg-sidebar-accent text-sidebar-accent-foreground shadow-sm"
                        : "text-sidebar-foreground/70 hover:bg-sidebar-accent/50 hover:text-sidebar-accent-foreground",
                    )}
                    style={
                      active && item.accent
                        ? { boxShadow: `inset 2px 0 0 ${item.accent}` }
                        : undefined
                    }
                  >
                    <Icon
                      className={cn(
                        "h-4 w-4 shrink-0 transition-colors",
                        active ? "text-foreground" : "text-muted-foreground group-hover:text-foreground",
                      )}
                      style={active && item.accent ? { color: item.accent } : undefined}
                    />
                    <span className="truncate font-medium">{item.label}</span>
                  </button>
                </li>
              );
            })}
          </ul>
        </nav>

        {/* Connection status */}
        <div className="border-t border-sidebar-border px-3 py-2.5">
          <div className="rounded-md bg-sidebar-accent/40 p-2.5">
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
            {sessionId && (
              <div className="flex items-center gap-2 font-mono-data text-[10px] text-muted-foreground">
                <ShieldCheck className="h-3.5 w-3.5 text-[color:var(--soc-success)]" />
                <span>Authorized Lab Scope</span>
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
    </div>
  );
}
