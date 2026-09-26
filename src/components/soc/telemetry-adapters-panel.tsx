"use client";

import { useCallback, useEffect, useState } from "react";
import {
  Activity,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Loader2,
  RefreshCw,
  Terminal,
  XCircle,
  type LucideIcon,
} from "lucide-react";
import { api } from "@/lib/api-client";
import type { AdapterConfig, AdapterInfo } from "@/lib/monitoring/adapters";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { toast } from "sonner";
import { cn } from "@/lib/utils";

// ============================================================
// TelemetryAdaptersPanel
//
// Replaces the simple "Telemetry Collectors" toggle grid in the
// Settings view with rich adapter status cards. Each card shows:
//   * Display name + description
//   * Availability badge (Available / Unavailable) with reason tooltip
//   * The original enable/disable toggle (kept functional — controls
//     whether the adapter WOULD be used if available)
//   * A "Test" button that POSTs a default config to /api/adapters
//     and shows the validation result.
//   * A collapsible config section with key per-adapter options
//     (read-only display with a note that backend setup is required).
//
// The component fetches status from /api/adapters on mount and on
// "Refresh Status" click.
// ============================================================

interface AdapterToggleConfig {
  /** The settings key this adapter's toggle controls. */
  settingsKey:
    | "enableNetworkCollector"
    | "enableSystemLogsCollector"
    | "enableWebLogsCollector"
    | "enableFirewallCollector"
    | "enableIdsCollector";
  enabled: boolean;
  onToggle: (v: boolean) => void;
}

interface Props {
  /** Current settings + setter from the parent form. */
  toggles: Record<AdapterInfo["name"], AdapterToggleConfig>;
  /** Default target address to use for the Test button. */
  defaultTarget: string;
}

// Per-adapter default config for the Test button. Uses a lab IP.
const TEST_TARGET = "192.168.1.100";

function defaultConfigFor(name: AdapterInfo["name"]): AdapterConfig {
  switch (name) {
    case "nmap":
      return { targetAddress: TEST_TARGET, options: { topPorts: 100, timeoutSec: 30 } };
    case "journald":
      return { targetAddress: TEST_TARGET, options: {} };
    case "nginx":
      return {
        targetAddress: TEST_TARGET,
        options: { logPath: "/var/log/nginx/access.log", parser: "combined" },
      };
    case "iptables":
      return {
        targetAddress: TEST_TARGET,
        options: { logPath: "/var/log/kern.log", source: "auto" },
      };
    case "suricata":
      return {
        targetAddress: TEST_TARGET,
        options: { eveJsonPath: "/var/log/suricata/eve.json" },
      };
    default:
      return { targetAddress: TEST_TARGET, options: {} };
  }
}

// Per-adapter config field descriptors for the read-only display.
interface ConfigField {
  label: string;
  key: string;
  placeholder: string;
}
const ADAPTER_CONFIG_FIELDS: Record<AdapterInfo["name"], ConfigField[]> = {
  nmap: [
    { label: "Top Ports", key: "topPorts", placeholder: "100" },
    { label: "Timeout (s)", key: "timeoutSec", placeholder: "30" },
  ],
  journald: [
    { label: "Units filter (comma-separated)", key: "units", placeholder: "ssh.service,sshd.service" },
  ],
  nginx: [
    { label: "Log path", key: "logPath", placeholder: "/var/log/nginx/access.log" },
    { label: "Parser", key: "parser", placeholder: "combined | common" },
  ],
  iptables: [
    { label: "Log path", key: "logPath", placeholder: "/var/log/kern.log" },
    { label: "Source", key: "source", placeholder: "auto | file | dmesg" },
  ],
  suricata: [
    { label: "EVE.json path", key: "eveJsonPath", placeholder: "/var/log/suricata/eve.json" },
  ],
};

const SOURCE_ICON: Record<AdapterInfo["name"], LucideIcon> = {
  nmap: Terminal,
  journald: Terminal,
  nginx: Activity,
  iptables: Terminal,
  suricata: Activity,
};

export function TelemetryAdaptersPanel({ toggles, defaultTarget }: Props) {
  void defaultTarget;
  const [adapters, setAdapters] = useState<AdapterInfo[]>([]);
  const [summary, setSummary] = useState<{ available: number; total: number } | null>(null);
  const [loading, setLoading] = useState(false);
  const [testingName, setTestingName] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [testResults, setTestResults] = useState<
    Record<string, { valid: boolean; issues: string[] } | null>
  >({});
  const [configEdits, setConfigEdits] = useState<
    Record<string, Record<string, string>>
  >({});

  const refresh = useCallback(async (force: boolean) => {
    setLoading(true);
    try {
      const res = await api.getAdapters(force);
      setAdapters(res.adapters);
      setSummary(res.summary);
      // Initialise config edit buffers from default config the first time
      setConfigEdits((prev) => {
        const next = { ...prev };
        for (const a of res.adapters) {
          if (!next[a.name]) {
            const cfg = defaultConfigFor(a.name);
            const opts = cfg.options ?? {};
            const buf: Record<string, string> = {};
            for (const [k, v] of Object.entries(opts)) {
              buf[k] = Array.isArray(v) ? v.join(",") : String(v);
            }
            next[a.name] = buf;
          }
        }
        return next;
      });
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Failed to load adapter status.";
      toast.error(msg);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh(false);
  }, [refresh]);

  const handleTest = async (name: AdapterInfo["name"]) => {
    setTestingName(name);
    try {
      const buf = configEdits[name] ?? {};
      // Build an AdapterConfig from the edit buffer + defaults.
      const defaults = defaultConfigFor(name);
      const options: Record<string, unknown> = { ...(defaults.options ?? {}) };
      for (const field of ADAPTER_CONFIG_FIELDS[name]) {
        const raw = buf[field.key];
        if (raw === undefined || raw === "") continue;
        // Numeric coercion for nmap's topPorts/timeoutSec
        if (field.key === "topPorts" || field.key === "timeoutSec") {
          const n = parseInt(raw, 10);
          if (Number.isFinite(n)) options[field.key] = n;
        } else if (field.key === "units") {
          const units = raw
            .split(",")
            .map((u) => u.trim())
            .filter(Boolean);
          if (units.length > 0) options[field.key] = units;
        } else {
          options[field.key] = raw;
        }
      }
      const config: AdapterConfig = { targetAddress: TEST_TARGET, options };
      const res = await api.testAdapter(name, config);
      setTestResults((prev) => ({ ...prev, [name]: { valid: res.valid, issues: res.issues } }));
      if (res.valid) {
        toast.success(`${name}: config is valid`);
      } else {
        toast.warning(`${name}: ${res.issues.length} issue(s)`);
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Test failed.";
      toast.error(msg);
      setTestResults((prev) => ({
        ...prev,
        [name]: { valid: false, issues: [msg] },
      }));
    } finally {
      setTestingName(null);
    }
  };

  const toggleExpanded = (name: string) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(name)) next.delete(name);
      else next.add(name);
      return next;
    });
  };

  return (
    <div className="space-y-2.5">
      {/* Summary bar */}
      <div className="flex flex-wrap items-center justify-between gap-2 rounded-md border border-border/40 bg-card/30 px-3 py-2">
        <div className="flex items-center gap-2 text-[11px]">
          {loading ? (
            <Loader2 className="h-3.5 w-3.5 animate-spin text-muted-foreground" />
          ) : summary && summary.available > 0 ? (
            <CheckCircle2 className="h-3.5 w-3.5 text-[color:var(--soc-success)]" />
          ) : (
            <XCircle className="h-3.5 w-3.5 text-[color:var(--soc-medium)]" />
          )}
          <span className="font-mono-data uppercase tracking-wider text-foreground/90">
            {summary ? `${summary.available} of ${summary.total} adapters available` : "Loading adapters…"}
          </span>
          <span className="text-[10px] text-muted-foreground">
            Real telemetry adapters run on the host (nmap, journalctl, log files). Unavailable adapters fall back to demo telemetry.
          </span>
        </div>
        <Button
          size="sm"
          variant="outline"
          onClick={() => void refresh(true)}
          disabled={loading}
          className="h-7 gap-1.5 text-[11px]"
        >
          <RefreshCw className={cn("h-3 w-3", loading && "animate-spin")} />
          Refresh Status
        </Button>
      </div>

      {/* Adapter cards */}
      <div className="space-y-2">
        {adapters.map((a) => {
          const toggle = toggles[a.name];
          const isExpanded = expanded.has(a.name);
          const Icon = SOURCE_ICON[a.name];
          const result = testResults[a.name];
          const isTesting = testingName === a.name;
          return (
            <div
              key={a.name}
              className={cn(
                "rounded-md border bg-card/30",
                a.status.available
                  ? "border-[color:var(--soc-success)]/40"
                  : "border-[color:var(--soc-medium)]/30",
              )}
            >
              {/* Header row */}
              <div className="flex flex-wrap items-start gap-2 px-3 py-2.5">
                <div className="flex min-w-0 flex-1 items-start gap-2">
                  <div className="mt-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-md border border-border/40 bg-muted/40">
                    <Icon className="h-3.5 w-3.5 text-muted-foreground" />
                  </div>
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="font-mono-data text-[12px] font-semibold uppercase tracking-wider text-foreground">
                        {a.displayName}
                      </span>
                      <StatusBadge available={a.status.available} reason={a.status.reason} version={a.status.version} />
                    </div>
                    <p className="mt-0.5 text-[10px] leading-snug text-muted-foreground">
                      {a.description}
                    </p>
                    {a.status.version && a.status.available && (
                      <p className="mt-0.5 font-mono-data text-[10px] text-[color:var(--soc-success)]/80">
                        {a.status.version}
                      </p>
                    )}
                  </div>
                </div>
                <div className="flex shrink-0 items-center gap-2">
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => void handleTest(a.name)}
                    disabled={isTesting}
                    className="h-7 gap-1.5 text-[10px]"
                    title="Validate a default config against this adapter"
                  >
                    {isTesting ? <Loader2 className="h-3 w-3 animate-spin" /> : <Activity className="h-3 w-3" />}
                    Test
                  </Button>
                  <div className="flex items-center gap-1.5">
                    <Label
                      htmlFor={`toggle-${a.name}`}
                      className="font-mono-data text-[10px] uppercase tracking-wider text-muted-foreground"
                    >
                      {toggle?.enabled ? "On" : "Off"}
                    </Label>
                    <Switch
                      id={`toggle-${a.name}`}
                      checked={toggle?.enabled ?? false}
                      onCheckedChange={(v) => toggle?.onToggle(v)}
                      disabled={!toggle}
                    />
                  </div>
                  <button
                    type="button"
                    onClick={() => toggleExpanded(a.name)}
                    className="rounded p-1 text-muted-foreground hover:bg-muted/40 hover:text-foreground"
                    aria-label={isExpanded ? "Collapse config" : "Expand config"}
                  >
                    {isExpanded ? <ChevronDown className="h-3.5 w-3.5" /> : <ChevronRight className="h-3.5 w-3.5" />}
                  </button>
                </div>
              </div>

              {/* Test result */}
              {result && (
                <div
                  className={cn(
                    "mx-3 mb-2 rounded border px-2.5 py-1.5 text-[10px]",
                    result.valid
                      ? "border-[color:var(--soc-success)]/40 bg-[color:var(--soc-success)]/10 text-[color:var(--soc-success)]"
                      : "border-[color:var(--soc-medium)]/40 bg-[color:var(--soc-medium)]/10 text-[color:var(--soc-medium)]",
                  )}
                >
                  <div className="font-mono-data uppercase tracking-wider">
                    {result.valid ? "Config valid" : `${result.issues.length} issue(s)`}
                  </div>
                  {!result.valid && (
                    <ul className="mt-1 list-inside list-disc space-y-0.5">
                      {result.issues.map((iss, i) => (
                        <li key={i}>{iss}</li>
                      ))}
                    </ul>
                  )}
                </div>
              )}

              {/* Collapsible config */}
              {isExpanded && (
                <div className="border-t border-border/30 bg-muted/10 px-3 py-2.5">
                  <div className="mb-2 font-mono-data text-[10px] uppercase tracking-wider text-muted-foreground">
                    Adapter Configuration
                  </div>
                  <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                    {ADAPTER_CONFIG_FIELDS[a.name].map((field) => {
                      const value = configEdits[a.name]?.[field.key] ?? "";
                      return (
                        <div key={field.key} className="space-y-1">
                          <Label
                            htmlFor={`cfg-${a.name}-${field.key}`}
                            className="font-mono-data text-[10px] uppercase tracking-wider text-foreground/80"
                          >
                            {field.label}
                          </Label>
                          <Input
                            id={`cfg-${a.name}-${field.key}`}
                            value={value}
                            placeholder={field.placeholder}
                            onChange={(e) =>
                              setConfigEdits((prev) => ({
                                ...prev,
                                [a.name]: { ...(prev[a.name] ?? {}), [field.key]: e.target.value },
                              }))
                            }
                            className="h-7 font-mono-data text-[10px]"
                          />
                        </div>
                      );
                    })}
                  </div>
                  <p className="mt-2 text-[10px] leading-snug text-muted-foreground">
                    <span className="font-mono-data uppercase tracking-wider">Note:</span>{" "}
                    Adapters run on the LiveSOC server (Node runtime). Configuration
                    requires backend setup (install nmap, configure log file
                    permissions, point at your EVE.json, etc.). The Test button
                    validates the config shape only — actual telemetry ingestion
                    requires the underlying tool to be available.
                  </p>
                </div>
              )}
            </div>
          );
        })}

        {adapters.length === 0 && !loading && (
          <div className="rounded-md border border-dashed border-border/40 px-3 py-6 text-center text-[11px] text-muted-foreground">
            No adapters loaded. Click <span className="font-mono-data">Refresh Status</span>.
          </div>
        )}
      </div>
    </div>
  );
}

// ---- Status badge ----

function StatusBadge({
  available,
  reason,
  version,
}: {
  available: boolean;
  reason?: string;
  version?: string;
}) {
  const tooltip = available
    ? version
      ? `Available: ${version}`
      : "Available"
    : reason
      ? `Unavailable: ${reason}`
      : "Unavailable";
  return (
    <span
      title={tooltip}
      className={cn(
        "inline-flex items-center gap-1 rounded border px-1.5 py-0.5 font-mono-data text-[9px] font-semibold uppercase tracking-wider",
        available
          ? "border-[color:var(--soc-success)]/40 bg-[color:var(--soc-success)]/10 text-[color:var(--soc-success)]"
          : "border-[color:var(--soc-medium)]/40 bg-[color:var(--soc-medium)]/10 text-[color:var(--soc-medium)]",
      )}
    >
      {available ? <CheckCircle2 className="h-2.5 w-2.5" /> : <XCircle className="h-2.5 w-2.5" />}
      {available ? "Available" : "Unavailable"}
    </span>
  );
}
