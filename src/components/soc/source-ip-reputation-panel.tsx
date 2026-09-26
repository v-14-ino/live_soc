"use client";

import { useMemo } from "react";
import type { SecurityEvent, Severity } from "@/lib/types";
import { severityColor, SEVERITY_LABEL } from "@/lib/constants";
import { Panel } from "@/components/soc/panel";
import { Fingerprint, AlertTriangle, ShieldCheck, ShieldAlert, Eye } from "lucide-react";

interface SourceIpReputationPanelProps {
  events: SecurityEvent[];
  className?: string;
}

// ============================================================
// Source IP Reputation Panel
//
// Analyzes observed source IPs and assigns a reputation tier
// based on their activity patterns within the current session:
//   - Activity volume (event count)
//   - Severity of events triggered
//   - Number of distinct target ports probed
//   - Whether they triggered alerts (auth failures, scans)
//   - First/last seen duration (burst vs sustained)
//
// Reputation tiers:
//   MALICIOUS (red)    — multiple high/critical events, multi-port probing
//   SUSPICIOUS (amber) — repeated medium events or auth failures
//   WATCHLIST (cyan)   — new source or low-severity anomaly
//   BENIGN (green)     — single low-severity event, normal access
// ============================================================

type ReputationTier = "malicious" | "suspicious" | "watchlist" | "benign";

interface IpReputation {
  ip: string;
  eventCount: number;
  portCount: number;
  topSeverity: Severity;
  severityBreakdown: Record<Severity, number>;
  firstSeen: number;
  lastSeen: number;
  durationSec: number;
  tier: ReputationTier;
  score: number; // 0-100, higher = worse
  signals: string[]; // human-readable reasons
  eventTypes: Set<string>;
}

const TIER_CONFIG: Record<ReputationTier, { color: string; label: string; icon: typeof ShieldAlert }> = {
  malicious: { color: "var(--soc-critical)", label: "Malicious", icon: ShieldAlert },
  suspicious: { color: "var(--soc-high)", label: "Suspicious", icon: AlertTriangle },
  watchlist: { color: "var(--soc-low)", label: "Watchlist", icon: Eye },
  benign: { color: "var(--soc-success)", label: "Benign", icon: ShieldCheck },
};

const SEV_RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

function computeTier(score: number): ReputationTier {
  if (score >= 70) return "malicious";
  if (score >= 40) return "suspicious";
  if (score >= 15) return "watchlist";
  return "benign";
}

export function SourceIpReputationPanel({ events, className }: SourceIpReputationPanelProps) {
  const reputations = useMemo<IpReputation[]>(() => {
    const map = new Map<string, {
      eventCount: number;
      ports: Set<number>;
      sevBreakdown: Record<Severity, number>;
      topSev: Severity;
      firstSeen: number;
      lastSeen: number;
      eventTypes: Set<string>;
    }>();

    for (const e of events) {
      if (!e.sourceIp) continue;
      const existing = map.get(e.sourceIp);
      const t = new Date(e.timestamp).getTime();
      if (existing) {
        existing.eventCount++;
        if (e.destPort != null) existing.ports.add(e.destPort);
        existing.sevBreakdown[e.severity]++;
        if (SEV_RANK[e.severity] > SEV_RANK[existing.topSev]) {
          existing.topSev = e.severity;
        }
        existing.firstSeen = Math.min(existing.firstSeen, t);
        existing.lastSeen = Math.max(existing.lastSeen, t);
        existing.eventTypes.add(e.eventType);
      } else {
        const ports = new Set<number>();
        if (e.destPort != null) ports.add(e.destPort);
        const sevBreakdown: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
        sevBreakdown[e.severity]++;
        map.set(e.sourceIp, {
          eventCount: 1,
          ports,
          sevBreakdown,
          topSev: e.severity,
          firstSeen: t,
          lastSeen: t,
          eventTypes: new Set([e.eventType]),
        });
      }
    }

    const result: IpReputation[] = [];
    for (const [ip, info] of map) {
      const durationSec = Math.max(1, Math.round((info.lastSeen - info.firstSeen) / 1000));
      const signals: string[] = [];
      let score = 0;

      // Volume scoring
      if (info.eventCount >= 50) { score += 25; signals.push(`${info.eventCount} events (high volume)`); }
      else if (info.eventCount >= 20) { score += 15; signals.push(`${info.eventCount} events`); }
      else if (info.eventCount >= 5) { score += 8; }
      else { score += 2; }

      // Severity scoring
      if (info.topSev === "critical") { score += 30; signals.push("Triggered critical severity"); }
      else if (info.topSev === "high") { score += 22; signals.push("Triggered high severity (auth failures)"); }
      else if (info.topSev === "medium") { score += 12; signals.push("Triggered medium severity"); }
      else if (info.topSev === "low") { score += 5; }

      // Port spread scoring (scanning behavior)
      if (info.ports.size >= 5) { score += 20; signals.push(`Probed ${info.ports.size} distinct ports (scan pattern)`); }
      else if (info.ports.size >= 3) { score += 10; signals.push(`Accessed ${info.ports.size} ports`); }
      else if (info.ports.size >= 2) { score += 4; }

      // Event type signals
      if (info.eventTypes.has("auth_failure")) { score += 8; signals.push("Authentication failures observed"); }
      if (info.eventTypes.has("port_probe")) { score += 8; signals.push("Port probing behavior"); }
      if (info.eventTypes.has("http_request") && info.eventCount >= 10) { score += 5; signals.push("High HTTP request volume"); }

      // Burst pattern (many events in short time)
      const ratePerSec = info.eventCount / durationSec;
      if (ratePerSec >= 2) { score += 8; signals.push(`Burst rate ${ratePerSec.toFixed(1)}/s`); }

      score = Math.min(100, score);
      const tier = computeTier(score);

      result.push({
        ip,
        eventCount: info.eventCount,
        portCount: info.ports.size,
        topSeverity: info.topSev,
        severityBreakdown: info.sevBreakdown,
        firstSeen: info.firstSeen,
        lastSeen: info.lastSeen,
        durationSec,
        tier,
        score,
        signals,
        eventTypes: info.eventTypes,
      });
    }

    // Sort by score desc (worst first)
    result.sort((a, b) => b.score - a.score);
    return result.slice(0, 10); // top 10
  }, [events]);

  const tierCounts = useMemo(() => {
    const counts: Record<ReputationTier, number> = { malicious: 0, suspicious: 0, watchlist: 0, benign: 0 };
    for (const r of reputations) counts[r.tier]++;
    return counts;
  }, [reputations]);

  return (
    <Panel
      title="Source IP Reputation"
      subtitle="Reputation tiers derived from observed activity patterns"
      icon={<Fingerprint className="h-4 w-4" />}
      className={className}
      bodyClassName="p-3"
    >
      {reputations.length === 0 ? (
        <div className="flex h-32 items-center justify-center">
          <div className="text-center">
            <Fingerprint className="mx-auto h-8 w-8 text-muted-foreground/30" />
            <p className="mt-2 font-mono-data text-[10px] uppercase tracking-wider text-muted-foreground/60">
              Waiting for source activity…
            </p>
          </div>
        </div>
      ) : (
        <div className="space-y-3">
          {/* Tier summary */}
          <div className="grid grid-cols-4 gap-1.5">
            {(Object.keys(TIER_CONFIG) as ReputationTier[]).map((tier) => {
              const cfg = TIER_CONFIG[tier];
              const Icon = cfg.icon;
              const count = tierCounts[tier];
              return (
                <div
                  key={tier}
                  className="rounded-md border border-border/40 bg-background/30 p-2 text-center"
                  style={count > 0 ? { borderColor: `color-mix(in oklch, ${cfg.color} 30%, transparent)` } : undefined}
                >
                  <Icon
                    className="mx-auto h-3.5 w-3.5"
                    style={{ color: count > 0 ? cfg.color : "var(--muted-foreground)" }}
                  />
                  <div
                    className="mt-1 font-mono-data text-lg font-bold leading-none"
                    style={{ color: count > 0 ? cfg.color : "var(--muted-foreground)" }}
                  >
                    {count}
                  </div>
                  <div className="mt-0.5 font-mono-data text-[8px] uppercase tracking-wider text-muted-foreground">
                    {cfg.label}
                  </div>
                </div>
              );
            })}
          </div>

          {/* IP list */}
          <div className="soc-scrollbar max-h-[400px] space-y-1.5 overflow-y-auto pr-1">
            {reputations.map((r) => {
              const cfg = TIER_CONFIG[r.tier];
              const Icon = cfg.icon;
              return (
                <div
                  key={r.ip}
                  className="rounded-md border bg-card/30 p-2.5 transition-colors hover:bg-card/50"
                  style={{ borderColor: `color-mix(in oklch, ${cfg.color} 25%, var(--border))` }}
                >
                  {/* Header row */}
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex min-w-0 items-center gap-2">
                      <Icon className="h-3.5 w-3.5 shrink-0" style={{ color: cfg.color }} />
                      <span className="truncate font-mono-data text-xs font-semibold text-foreground">
                        {r.ip}
                      </span>
                    </div>
                    <div className="flex shrink-0 items-center gap-1.5">
                      <span
                        className="rounded-sm border px-1.5 py-0.5 font-mono-data text-[9px] font-bold uppercase tracking-wider"
                        style={{
                          color: cfg.color,
                          borderColor: `color-mix(in oklch, ${cfg.color} 40%, transparent)`,
                          backgroundColor: `color-mix(in oklch, ${cfg.color} 12%, transparent)`,
                        }}
                      >
                        {cfg.label}
                      </span>
                      <span
                        className="font-mono-data text-xs font-bold"
                        style={{ color: cfg.color }}
                      >
                        {r.score}
                      </span>
                    </div>
                  </div>

                  {/* Score bar */}
                  <div className="mt-1.5 h-1 w-full overflow-hidden rounded-full bg-muted">
                    <div
                      className="h-full rounded-full transition-all duration-500"
                      style={{
                        width: `${r.score}%`,
                        backgroundColor: cfg.color,
                        boxShadow: r.score > 50 ? `0 0 4px ${cfg.color}` : "none",
                      }}
                    />
                  </div>

                  {/* Stats row */}
                  <div className="mt-1.5 flex flex-wrap items-center gap-x-2 gap-y-0.5 font-mono-data text-[9px] text-muted-foreground">
                    <span>{r.eventCount} events</span>
                    <span className="text-muted-foreground/40">·</span>
                    <span>{r.portCount} ports</span>
                    <span className="text-muted-foreground/40">·</span>
                    <span style={{ color: severityColor(r.topSeverity) }}>
                      {SEVERITY_LABEL[r.topSeverity]}
                    </span>
                    <span className="text-muted-foreground/40">·</span>
                    <span>{r.durationSec}s active</span>
                  </div>

                  {/* Signals (top 2) */}
                  {r.signals.length > 0 && (
                    <div className="mt-1.5 space-y-0.5">
                      {r.signals.slice(0, 2).map((sig, i) => (
                        <div key={i} className="flex items-start gap-1 text-[9px] text-muted-foreground">
                          <span className="mt-0.5 text-[color:var(--soc-medium)]">▸</span>
                          <span className="leading-tight">{sig}</span>
                        </div>
                      ))}
                      {r.signals.length > 2 && (
                        <div className="text-[8px] text-muted-foreground/60">+{r.signals.length - 2} more</div>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>

          {/* Disclaimer */}
          <div className="rounded-md border border-[color:var(--soc-medium)]/30 bg-[color:var(--soc-medium)]/5 p-2 text-[9px] text-muted-foreground leading-relaxed">
            Reputation tiers are derived from observed telemetry patterns within this session only. They represent potential risk based on activity — not confirmed malicious intent. Verify against authorized assessment scope.
          </div>
        </div>
      )}
    </Panel>
  );
}
