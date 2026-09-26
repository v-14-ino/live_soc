"use client";

import { useMemo } from "react";
import type { OffenseScenario } from "@/lib/types";
import { severityColor } from "@/lib/constants";
import { Panel } from "@/components/soc/panel";
import { Crosshair } from "lucide-react";

interface MitreMatrixPanelProps {
  scenarios: OffenseScenario[];
  className?: string;
}

// ============================================================
// MITRE ATT&CK Coverage Matrix
//
// Shows a grid of MITRE ATT&CK techniques observed in offense
// scenarios. Each technique is a cell colored by the highest
// severity scenario that references it. Unobserved techniques
// are dimmed.
// ============================================================

interface MitreTechnique {
  id: string;
  name: string;
  tactic: string;
}

// Techniques used by the offense templates (from constants.ts OFFENSE_TEMPLATES)
const MITRE_TECHNIQUES: MitreTechnique[] = [
  { id: "T1046", name: "Network Service Discovery", tactic: "Discovery" },
  { id: "T1110", name: "Brute Force", tactic: "Credential Access" },
  { id: "T1190", name: "Exploit Public-Facing App", tactic: "Initial Access" },
  { id: "T1595", name: "Active Scanning", tactic: "Reconnaissance" },
  { id: "T1082", name: "System Info Discovery", tactic: "Discovery" },
  { id: "T1592", name: "Gather Victim Host Info", tactic: "Reconnaissance" },
];

const TACTIC_ORDER = [
  "Reconnaissance",
  "Initial Access",
  "Discovery",
  "Credential Access",
];

export function MitreMatrixPanel({ scenarios, className }: MitreMatrixPanelProps) {
  const { observed, byTechnique, byTactic } = useMemo(() => {
    const byTechnique = new Map<string, { scenarios: OffenseScenario[]; maxSeverity: string }>();
    for (const s of scenarios) {
      const tid = s.techniqueMitre;
      if (!tid) continue;
      const existing = byTechnique.get(tid);
      if (existing) {
        existing.scenarios.push(s);
      } else {
        byTechnique.set(tid, { scenarios: [s], maxSeverity: s.severity });
      }
    }
    // Compute max severity per technique
    const sevRank: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
    for (const [, info] of byTechnique) {
      info.maxSeverity = info.scenarios.reduce((max, s) =>
        sevRank[s.severity] > sevRank[max] ? s.severity : max, "info");
    }

    // Group techniques by tactic
    const byTactic = new Map<string, MitreTechnique[]>();
    for (const t of MITRE_TECHNIQUES) {
      const arr = byTactic.get(t.tactic) ?? [];
      arr.push(t);
      byTactic.set(t.tactic, arr);
    }

    return { observed: byTechnique.size, byTechnique, byTactic };
  }, [scenarios]);

  return (
    <Panel
      title="MITRE ATT&CK Coverage"
      subtitle={`${observed} of ${MITRE_TECHNIQUES.length} techniques observed`}
      icon={<Crosshair className="h-4 w-4" />}
      className={className}
      bodyClassName="p-3"
    >
      <div className="space-y-3">
        {TACTIC_ORDER.map((tactic) => {
          const techniques = byTactic.get(tactic) ?? [];
          return (
            <div key={tactic}>
              <div className="mb-1.5 flex items-center gap-2">
                <span className="font-mono-data text-[9px] uppercase tracking-wider text-muted-foreground">
                  {tactic}
                </span>
                <div className="h-px flex-1 bg-border/40" />
              </div>
              <div className="grid grid-cols-2 gap-1.5 sm:grid-cols-3">
                {techniques.map((tech) => {
                  const info = byTechnique.get(tech.id);
                  const isObserved = !!info;
                  const sevColor = isObserved ? severityColor(info!.maxSeverity as never) : "var(--muted-foreground)";
                  return (
                    <div
                      key={tech.id}
                      className="group relative rounded-md border p-2 transition-all"
                      style={{
                        borderColor: isObserved
                          ? `color-mix(in oklch, ${sevColor} 40%, transparent)`
                          : "var(--border)",
                        backgroundColor: isObserved
                          ? `color-mix(in oklch, ${sevColor} 10%, transparent)`
                          : "color-mix(in oklch, var(--muted) 20%, transparent)",
                        opacity: isObserved ? 1 : 0.5,
                      }}
                      title={isObserved ? `${tech.name} — ${info!.scenarios.length} scenario(s)` : `${tech.name} — not observed`}
                    >
                      <div className="flex items-center justify-between gap-1">
                        <span
                          className="font-mono-data text-[10px] font-bold"
                          style={{ color: sevColor }}
                        >
                          {tech.id}
                        </span>
                        {isObserved && (
                          <span
                            className="inline-block h-1.5 w-1.5 rounded-full"
                            style={{ backgroundColor: sevColor, boxShadow: `0 0 4px ${sevColor}` }}
                          />
                        )}
                      </div>
                      <div className="mt-0.5 truncate text-[9px] text-foreground/70" title={tech.name}>
                        {tech.name}
                      </div>
                      {isObserved && info!.scenarios.length > 1 && (
                        <div className="mt-0.5 font-mono-data text-[8px] text-muted-foreground">
                          {info!.scenarios.length}× observed
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          );
        })}

        {/* Legend */}
        <div className="flex items-center gap-3 border-t border-border/40 pt-2 font-mono-data text-[8px] uppercase tracking-wider text-muted-foreground">
          <span className="flex items-center gap-1">
            <span className="inline-block h-2 w-2 rounded-sm" style={{ background: "var(--soc-critical)" }} />
            Critical
          </span>
          <span className="flex items-center gap-1">
            <span className="inline-block h-2 w-2 rounded-sm" style={{ background: "var(--soc-high)" }} />
            High
          </span>
          <span className="flex items-center gap-1">
            <span className="inline-block h-2 w-2 rounded-sm" style={{ background: "var(--soc-medium)" }} />
            Medium
          </span>
          <span className="flex items-center gap-1">
            <span className="inline-block h-2 w-2 rounded-sm" style={{ background: "var(--soc-low)" }} />
            Low
          </span>
          <span className="flex items-center gap-1 opacity-50">
            <span className="inline-block h-2 w-2 rounded-sm border border-border" />
            Not observed
          </span>
        </div>
      </div>
    </Panel>
  );
}
