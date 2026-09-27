"use client";

import { useEffect, useMemo, useState, type ReactNode } from "react";
import {
  Settings as SettingsIcon,
  Save,
  RotateCcw,
  Trash2,
  Activity,
  Radar,
  Shield,
  AlertTriangle,
  Webhook,
  CheckCircle2,
  Database,
  Cpu,
  MonitorSmartphone,
  type LucideIcon,
} from "lucide-react";
import { useAppStore } from "@/lib/store";
import { api } from "@/lib/api-client";
import { AuthWarning } from "@/components/soc/auth-warning";
import { TelemetryAdaptersPanel } from "@/components/soc/telemetry-adapters-panel";
import { WebhooksPanel } from "@/components/soc/webhooks-panel";
import { AgentManagementPanel } from "@/components/soc/agent-management-panel";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Slider } from "@/components/ui/slider";
import { Textarea } from "@/components/ui/textarea";
import { Skeleton } from "@/components/ui/skeleton";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import { toast } from "sonner";
import { AUTHORIZED_SCOPE_NOTICE, DEFAULT_SETTINGS } from "@/lib/constants";
import type { AppSettings } from "@/lib/types";

// ============================================================
// Helpers
// ============================================================

function hasChanges(local: AppSettings, store: AppSettings): boolean {
  return (Object.keys(local) as (keyof AppSettings)[]).some(
    (k) => local[k] !== store[k],
  );
}

function diffPatch(local: AppSettings, store: AppSettings): Partial<AppSettings> {
  const patch: Partial<AppSettings> = {};
  (Object.keys(local) as (keyof AppSettings)[]).forEach((k) => {
    if (local[k] !== store[k]) {
      // @ts-expect-error index assignment
      patch[k] = local[k];
    }
  });
  return patch;
}

// ============================================================
// Small UI atoms
// ============================================================

function SectionLabel({ children }: { children: ReactNode }) {
  return (
    <div className="font-mono-data text-[10px] font-semibold uppercase tracking-wider text-muted-foreground/80">
      {children}
    </div>
  );
}

function SectionCard({
  title,
  description,
  icon: Icon,
  children,
}: {
  title: string;
  description?: string;
  icon: LucideIcon;
  children: ReactNode;
}) {
  return (
    <section className="overflow-hidden rounded-lg border border-border/40 bg-card/40">
      <div className="flex items-center gap-2 border-b border-border/40 bg-card/30 px-3 py-2.5">
        <Icon className="h-4 w-4 text-muted-foreground" />
        <div className="min-w-0">
          <h3 className="font-mono-data text-[11px] font-semibold uppercase tracking-wider text-foreground">
            {title}
          </h3>
          {description && (
            <p className="truncate text-[10px] text-muted-foreground">{description}</p>
          )}
        </div>
      </div>
      <div className="p-3">{children}</div>
    </section>
  );
}

function FieldRow({
  label,
  htmlFor,
  description,
  children,
}: {
  label: string;
  htmlFor?: string;
  description?: string;
  children: ReactNode;
}) {
  return (
    <div className="grid grid-cols-1 gap-1.5 border-b border-border/30 py-2.5 last:border-b-0 sm:grid-cols-[200px_1fr] sm:gap-3">
      <div>
        <Label htmlFor={htmlFor} className="font-mono-data text-[11px] uppercase tracking-wider text-foreground/90">
          {label}
        </Label>
        {description && (
          <p className="mt-0.5 text-[10px] leading-snug text-muted-foreground">{description}</p>
        )}
      </div>
      <div className="min-w-0">{children}</div>
    </div>
  );
}

function ToggleRow({
  label,
  description,
  checked,
  onChange,
}: {
  label: string;
  description: string;
  checked: boolean;
  onChange: (v: boolean) => void;
}) {
  return (
    <div className="flex items-start justify-between gap-3 border-b border-border/30 py-2.5 last:border-b-0">
      <div className="min-w-0">
        <div className="font-mono-data text-[11px] uppercase tracking-wider text-foreground/90">
          {label}
        </div>
        <p className="mt-0.5 text-[10px] leading-snug text-muted-foreground">{description}</p>
      </div>
      <Switch checked={checked} onCheckedChange={onChange} className="mt-0.5 shrink-0" />
    </div>
  );
}

// ============================================================
// Header
// ============================================================

function SettingsHeader({
  saving,
  hasChanges: dirty,
  onSave,
  onReset,
}: {
  saving: boolean;
  hasChanges: boolean;
  onSave: () => void;
  onReset: () => void;
}) {
  return (
    <div className="shrink-0 border-b border-border/40 bg-card/30 px-4 py-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex min-w-0 items-center gap-2.5">
          <div className="flex h-7 w-7 items-center justify-center rounded-md border border-border/60 bg-muted/40">
            <SettingsIcon className="h-4 w-4 text-muted-foreground" />
          </div>
          <div className="min-w-0">
            <h2 className="font-mono-data text-sm font-bold uppercase tracking-wider text-foreground">
              Settings
            </h2>
            <p className="truncate text-[10px] text-muted-foreground">
              Platform configuration. Changes apply to new monitoring sessions.
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Button
            size="sm"
            variant="outline"
            onClick={onReset}
            disabled={saving}
            className="h-7 gap-1.5 text-[11px]"
          >
            <RotateCcw className="h-3 w-3" />
            Reset to Defaults
          </Button>
          <Button
            size="sm"
            onClick={onSave}
            disabled={!dirty || saving}
            className="h-7 gap-1.5 text-[11px]"
          >
            {saving ? <Activity className="h-3 w-3 animate-pulse" /> : <Save className="h-3 w-3" />}
            {saving ? "Saving…" : "Save Changes"}
          </Button>
        </div>
      </div>
      <div className="mt-2">
        <AuthWarning variant="banner" />
      </div>
    </div>
  );
}

// ============================================================
// Main view
// ============================================================

export function SettingsView() {
  const storeSettings = useAppStore((s) => s.settings);
  const setSettings = useAppStore((s) => s.setSettings);

  const [local, setLocal] = useState<AppSettings>(storeSettings);
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [clearing, setClearing] = useState(false);
  const [clearDialogOpen, setClearDialogOpen] = useState(false);

  // Sync local form when the store finishes its initial load
  useEffect(() => {
    setLocal(storeSettings);
  }, [storeSettings]);

  // Track whether store settings have been hydrated from the API.
  // The store defaults to DEFAULT_SETTINGS on mount; the actual API values
  // arrive a moment later via useSettingsLoader in page.tsx.
  const [hydrated, setHydrated] = useState(false);
  useEffect(() => {
    let alive = true;
    setLoading(true);
    api
      .getSettings()
      .then((s) => {
        if (!alive) return;
        setSettings(s);
        setLocal(s);
        setHydrated(true);
      })
      .catch(() => {
        // Fall back to defaults (already in store)
        setHydrated(true);
      })
      .finally(() => {
        if (alive) setLoading(false);
      });
    return () => {
      alive = false;
    };
  }, [setSettings]);

  const dirty = useMemo(() => hasChanges(local, storeSettings), [local, storeSettings]);

  const update = <K extends keyof AppSettings>(key: K, value: AppSettings[K]) => {
    setLocal((prev) => ({ ...prev, [key]: value }));
  };

  const handleSave = async () => {
    const patch = diffPatch(local, storeSettings);
    if (Object.keys(patch).length === 0) {
      toast.info("No changes to save.");
      return;
    }
    setSaving(true);
    try {
      const updated = await api.updateSettings(patch);
      setSettings(updated);
      setLocal(updated);
      toast.success("Settings saved.");
    } catch (e) {
      const msg = e instanceof Error ? e.message : "Failed to save settings.";
      toast.error(msg);
    } finally {
      setSaving(false);
    }
  };

  const handleReset = () => {
    setLocal({ ...DEFAULT_SETTINGS });
    toast.info("Form reset to defaults. Click Save to persist.");
  };

  const handleClearHistory = async () => {
    setClearing(true);
    try {
      const res = await fetch("/api/history", { method: "DELETE" });
      if (!res.ok) {
        const body = (await res.json().catch(() => null)) as { error?: string } | null;
        throw new Error(body?.error ?? `Request failed (${res.status})`);
      }
      const body = (await res.json().catch(() => null)) as { deleted?: Record<string, number> } | null;
      const counts = body?.deleted;
      const totalDeleted = counts
        ? Object.values(counts).reduce((a, b) => a + b, 0)
        : 0;
      toast.success(`Cleared ${totalDeleted} record(s) from history.`);
      setClearDialogOpen(false);
    } catch (e) {
      const msg = e instanceof Error ? e.message : "Failed to clear history.";
      toast.error(msg);
    } finally {
      setClearing(false);
    }
  };

  if (loading && !hydrated) {
    return (
      <div className="flex h-full flex-col overflow-hidden">
        <SettingsHeader
          saving={false}
          hasChanges={false}
          onSave={() => undefined}
          onReset={() => undefined}
        />
        <div className="soc-scrollbar flex-1 overflow-y-auto">
          <div className="mx-auto max-w-3xl space-y-3 p-3">
            <Skeleton className="h-40 w-full" />
            <Skeleton className="h-56 w-full" />
            <Skeleton className="h-40 w-full" />
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="flex h-full flex-col overflow-hidden">
      <SettingsHeader
        saving={saving}
        hasChanges={dirty}
        onSave={handleSave}
        onReset={handleReset}
      />

      <div className="soc-scrollbar min-h-0 flex-1 overflow-y-auto overflow-x-hidden">
        <div className="mx-auto max-w-3xl space-y-3 p-3">
          {/* MONITORING MODE */}
          <SectionCard
            title="Monitoring Mode"
            description="How telemetry is collected and rendered in the live view."
            icon={Cpu}
          >
            <ToggleRow
              label="Demo Mode"
              description="Use clearly-labeled simulated telemetry when real sources are unavailable."
              checked={local.demoMode}
              onChange={(v) => update("demoMode", v)}
            />
            <FieldRow
              label="Telemetry Interval"
              htmlFor="telemetryInterval"
              description="Interval between generated telemetry events (500–5000 ms)."
            >
              <div className="flex items-center gap-3 pt-1.5">
                <Slider
                  id="telemetryInterval"
                  min={500}
                  max={5000}
                  step={100}
                  value={[local.telemetryIntervalMs]}
                  onValueChange={(v) => update("telemetryIntervalMs", v[0] ?? local.telemetryIntervalMs)}
                  className="flex-1"
                />
                <span className="w-[80px] shrink-0 text-right font-mono-data text-[11px] text-foreground/90">
                  {local.telemetryIntervalMs} ms
                </span>
              </div>
            </FieldRow>
            <FieldRow
              label="Max Live Events"
              htmlFor="maxLiveEvents"
              description="Maximum events kept in the live UI view (100–2000)."
            >
              <Input
                id="maxLiveEvents"
                type="number"
                min={100}
                max={2000}
                step={50}
                value={local.maxLiveEvents}
                onChange={(e) => {
                  const v = Number(e.target.value);
                  if (!Number.isFinite(v)) return;
                  update("maxLiveEvents", Math.max(100, Math.min(2000, Math.floor(v))));
                }}
                className="h-8 w-full max-w-[160px] font-mono-data text-[11px]"
              />
            </FieldRow>
            <FieldRow
              label="Scan Timeout (s)"
              htmlFor="scanTimeout"
              description="Maximum time for an initial assessment scan (10–120 s)."
            >
              <Input
                id="scanTimeout"
                type="number"
                min={10}
                max={120}
                step={5}
                value={local.scanTimeoutSec}
                onChange={(e) => {
                  const v = Number(e.target.value);
                  if (!Number.isFinite(v)) return;
                  update("scanTimeoutSec", Math.max(10, Math.min(120, Math.floor(v))));
                }}
                className="h-8 w-full max-w-[160px] font-mono-data text-[11px]"
              />
            </FieldRow>
            <FieldRow
              label="Scan Top Ports"
              htmlFor="scanTopPorts"
              description="Maximum number of ports probed during initial assessment (10–1000)."
            >
              <Input
                id="scanTopPorts"
                type="number"
                min={10}
                max={1000}
                step={10}
                value={local.scanTopPorts}
                onChange={(e) => {
                  const v = Number(e.target.value);
                  if (!Number.isFinite(v)) return;
                  update("scanTopPorts", Math.max(10, Math.min(1000, Math.floor(v))));
                }}
                className="h-8 w-full max-w-[160px] font-mono-data text-[11px]"
              />
            </FieldRow>
            <FieldRow
              label="Agent Heartbeat Interval (s)"
              htmlFor="agentHeartbeatInterval"
              description="How often agents should send heartbeats (10–300 s)."
            >
              <Input
                id="agentHeartbeatInterval"
                type="number"
                min={10}
                max={300}
                step={5}
                value={local.agentHeartbeatIntervalSec}
                onChange={(e) => {
                  const v = Number(e.target.value);
                  if (!Number.isFinite(v)) return;
                  update("agentHeartbeatIntervalSec", Math.max(10, Math.min(300, Math.floor(v))));
                }}
                className="h-8 w-full max-w-[160px] font-mono-data text-[11px]"
              />
            </FieldRow>
            <FieldRow
              label="Agent Degraded After (s)"
              htmlFor="agentDegradedAfter"
              description="Seconds without heartbeat before an agent is marked DEGRADED (30–600 s)."
            >
              <Input
                id="agentDegradedAfter"
                type="number"
                min={30}
                max={600}
                step={10}
                value={local.agentDegradedAfterSec}
                onChange={(e) => {
                  const v = Number(e.target.value);
                  if (!Number.isFinite(v)) return;
                  update("agentDegradedAfterSec", Math.max(30, Math.min(600, Math.floor(v))));
                }}
                className="h-8 w-full max-w-[160px] font-mono-data text-[11px]"
              />
            </FieldRow>
            <FieldRow
              label="Agent Offline After (s)"
              htmlFor="agentOfflineAfter"
              description="Seconds without heartbeat before an agent is marked OFFLINE + alert generated (60–3600 s)."
            >
              <Input
                id="agentOfflineAfter"
                type="number"
                min={60}
                max={3600}
                step={30}
                value={local.agentOfflineAfterSec}
                onChange={(e) => {
                  const v = Number(e.target.value);
                  if (!Number.isFinite(v)) return;
                  update("agentOfflineAfterSec", Math.max(60, Math.min(3600, Math.floor(v))));
                }}
                className="h-8 w-full max-w-[160px] font-mono-data text-[11px]"
              />
            </FieldRow>
          </SectionCard>

          {/* TELEMETRY COLLECTORS */}
          <SectionCard
            title="Telemetry Collectors"
            description="Real telemetry adapters + enable/disable toggles for each source."
            icon={Radar}
          >
            <TelemetryAdaptersPanel
              defaultTarget={local.demoMode ? "192.168.1.100" : "192.168.1.100"}
              toggles={{
                nmap: {
                  settingsKey: "enableNetworkCollector",
                  enabled: local.enableNetworkCollector,
                  onToggle: (v) => update("enableNetworkCollector", v),
                },
                journald: {
                  settingsKey: "enableSystemLogsCollector",
                  enabled: local.enableSystemLogsCollector,
                  onToggle: (v) => update("enableSystemLogsCollector", v),
                },
                nginx: {
                  settingsKey: "enableWebLogsCollector",
                  enabled: local.enableWebLogsCollector,
                  onToggle: (v) => update("enableWebLogsCollector", v),
                },
                iptables: {
                  settingsKey: "enableFirewallCollector",
                  enabled: local.enableFirewallCollector,
                  onToggle: (v) => update("enableFirewallCollector", v),
                },
                suricata: {
                  settingsKey: "enableIdsCollector",
                  enabled: local.enableIdsCollector,
                  onToggle: (v) => update("enableIdsCollector", v),
                },
              }}
            />
          </SectionCard>

          {/* AUTHORIZED SCOPE */}
          <SectionCard
            title="Authorized Scope"
            description="Reminder of the scope boundary all monitoring must respect."
            icon={Shield}
          >
            <div className="flex items-start gap-2 rounded-md border border-[color:var(--soc-medium)]/40 bg-[color:var(--soc-medium)]/10 px-3 py-2.5 text-[11px] text-[color:var(--soc-medium)]">
              <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
              <div>
                <div className="font-mono-data text-[10px] font-semibold uppercase tracking-wider">
                  Notice
                </div>
                <div className="mt-0.5">{AUTHORIZED_SCOPE_NOTICE}</div>
              </div>
            </div>
            <div className="mt-3">
              <Label htmlFor="scopeNote" className="font-mono-data text-[11px] uppercase tracking-wider text-foreground/90">
                Authorized scope note
              </Label>
              <Textarea
                id="scopeNote"
                value={local.authorizedScopeNote}
                onChange={(e) => update("authorizedScopeNote", e.target.value)}
                rows={3}
                className="mt-1.5 font-mono-data text-[11px]"
                placeholder="Document the specific systems, addresses, or networks you are authorized to assess here."
              />
              <p className="mt-1 text-[10px] text-muted-foreground">
                This note is stored in settings and shown as a reminder. It does
                not modify backend target validation — backend enforcement is
                independent of this field.
              </p>
            </div>
          </SectionCard>

          {/* WEBHOOK NOTIFICATIONS */}
          <SectionCard
            title="Webhook Notifications"
            description="POST notifications to external endpoints when alerts fire."
            icon={Webhook}
          >
            <WebhooksPanel />
          </SectionCard>

          {/* AGENTS (Phase B) */}
          <SectionCard
            title="Agents"
            description="Register and manage telemetry agents (Linux/Windows)."
            icon={MonitorSmartphone}
          >
            <AgentManagementPanel />
          </SectionCard>

          {/* DATA MANAGEMENT */}
          <SectionCard
            title="Data Management"
            description="Persistent data lifecycle controls."
            icon={Database}
          >
            <div className="flex flex-col gap-2 rounded-md border border-border/40 bg-card/30 p-3 sm:flex-row sm:items-center sm:justify-between">
              <div className="min-w-0">
                <div className="font-mono-data text-[11px] font-semibold uppercase tracking-wider text-foreground">
                  Clear all history
                </div>
                <p className="mt-0.5 text-[10px] leading-snug text-muted-foreground">
                  Permanently delete all monitoring sessions, events, alerts,
                  scenarios, and reports from the database. This action is
                  irreversible and audit-logged.
                </p>
              </div>
              <AlertDialog open={clearDialogOpen} onOpenChange={setClearDialogOpen}>
                <AlertDialogTrigger asChild>
                  <Button
                    size="sm"
                    variant="destructive"
                    className="h-8 shrink-0 gap-1.5 text-[11px]"
                    disabled={clearing}
                  >
                    <Trash2 className="h-3 w-3" />
                    Clear All History
                  </Button>
                </AlertDialogTrigger>
                <AlertDialogContent>
                  <AlertDialogHeader>
                    <AlertDialogTitle className="font-mono-data uppercase tracking-wider">
                      Clear all monitoring history?
                    </AlertDialogTitle>
                    <AlertDialogDescription>
                      This will permanently delete <strong>all</strong>{" "}
                      monitoring sessions, events, alerts, offense/defense
                      scenarios, and reports from the database. The action is
                      irreversible and will be recorded in the audit log. Are
                      you absolutely sure?
                    </AlertDialogDescription>
                  </AlertDialogHeader>
                  <AlertDialogFooter>
                    <AlertDialogCancel disabled={clearing}>Cancel</AlertDialogCancel>
                    <AlertDialogAction
                      onClick={(e) => {
                        e.preventDefault();
                        void handleClearHistory();
                      }}
                      disabled={clearing}
                      className="gap-1.5 bg-[color:var(--soc-critical)] text-white hover:bg-[color:var(--soc-critical)]/90"
                    >
                      {clearing ? <Activity className="h-3.5 w-3.5 animate-pulse" /> : <Trash2 className="h-3.5 w-3.5" />}
                      {clearing ? "Clearing…" : "Yes, clear everything"}
                    </AlertDialogAction>
                  </AlertDialogFooter>
                </AlertDialogContent>
              </AlertDialog>
            </div>
          </SectionCard>

          {/* Save / status bar */}
          <div className="sticky bottom-0 -mx-3 -mb-3 flex items-center justify-between gap-2 border-t border-border/40 bg-card/80 px-3 py-2 backdrop-blur-md">
            <div className="flex items-center gap-2 text-[10px] text-muted-foreground">
              {dirty ? (
                <>
                  <AlertTriangle className="h-3 w-3 text-[color:var(--soc-medium)]" />
                  <span className="font-mono-data uppercase tracking-wider text-[color:var(--soc-medium)]">
                    Unsaved changes
                  </span>
                </>
              ) : (
                <>
                  <CheckCircle2 className="h-3 w-3 text-[color:var(--soc-success)]" />
                  <span className="font-mono-data uppercase tracking-wider text-[color:var(--soc-success)]">
                    All changes saved
                  </span>
                </>
              )}
            </div>
            <div className="flex items-center gap-1.5">
              <Button
                size="sm"
                variant="outline"
                onClick={handleReset}
                disabled={saving}
                className="h-7 gap-1.5 text-[11px]"
              >
                <RotateCcw className="h-3 w-3" />
                Reset
              </Button>
              <Button
                size="sm"
                onClick={handleSave}
                disabled={!dirty || saving}
                className="h-7 gap-1.5 text-[11px]"
              >
                {saving ? <Activity className="h-3 w-3 animate-pulse" /> : <Save className="h-3 w-3" />}
                {saving ? "Saving…" : "Save"}
              </Button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
