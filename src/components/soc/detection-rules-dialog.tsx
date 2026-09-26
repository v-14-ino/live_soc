"use client";

import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";
import { ScrollArea } from "@/components/ui/scroll-area";
import { SeverityBadge } from "@/components/soc/severity-badge";
import { DETECTION_RULES } from "@/lib/constants";
import { Search, Target, Gauge, ShieldCheck, BookOpen } from "lucide-react";

interface DetectionRulesDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export function DetectionRulesDialog({ open, onOpenChange }: DetectionRulesDialogProps) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[88vh] max-w-3xl overflow-hidden p-0 gap-0">
        <DialogHeader className="border-b border-border/60 px-5 py-4">
          <DialogTitle className="flex items-center gap-2 font-mono-data text-sm uppercase tracking-wider">
            <BookOpen className="h-4 w-4 text-[color:var(--soc-low)]" />
            Detection Rules Reference
          </DialogTitle>
          <DialogDescription className="text-xs">
            Rule-based detection engine — {DETECTION_RULES.length} active rules. Alerts are generated when telemetry matches these conditions. Never random.
          </DialogDescription>
        </DialogHeader>
        <ScrollArea className="max-h-[calc(88vh-80px)] soc-scrollbar">
          <div className="space-y-3 p-5">
            {DETECTION_RULES.map((rule) => (
              <div
                key={rule.ruleId}
                className="rounded-lg border border-border/60 bg-card/40 p-4"
              >
                <div className="mb-2 flex items-start justify-between gap-3">
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <span className="font-mono-data text-xs font-bold text-[color:var(--soc-low)]">
                        {rule.ruleId}
                      </span>
                      <SeverityBadge severity={rule.severity} size="sm" />
                      <span className="rounded-sm border border-border/60 px-1.5 py-0.5 font-mono-data text-[9px] uppercase tracking-wider text-muted-foreground">
                        {rule.category}
                      </span>
                    </div>
                    <h3 className="mt-1.5 text-sm font-semibold text-foreground">
                      {rule.name}
                    </h3>
                  </div>
                  <div className="shrink-0 text-right">
                    <div className="font-mono-data text-[10px] uppercase tracking-wider text-muted-foreground">Confidence</div>
                    <div className="font-mono-data text-lg font-bold" style={{ color: "var(--soc-low)" }}>
                      {rule.confidence}%
                    </div>
                  </div>
                </div>

                <p className="mb-3 text-xs text-muted-foreground leading-relaxed">
                  {rule.description}
                </p>

                <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                  <div className="rounded-md border border-border/40 bg-background/30 p-2.5">
                    <div className="mb-1 flex items-center gap-1.5 font-mono-data text-[9px] uppercase tracking-wider text-muted-foreground">
                      <Target className="h-3 w-3" />
                      Conditions
                    </div>
                    <p className="font-mono-data text-[11px] text-foreground/80 leading-relaxed">
                      {rule.conditions}
                    </p>
                  </div>
                  <div className="rounded-md border border-border/40 bg-background/30 p-2.5">
                    <div className="mb-1 flex items-center gap-1.5 font-mono-data text-[9px] uppercase tracking-wider text-muted-foreground">
                      <ShieldCheck className="h-3 w-3" />
                      Recommended Action
                    </div>
                    <p className="text-[11px] text-foreground/80 leading-relaxed">
                      {rule.recommendedAction}
                    </p>
                  </div>
                </div>
              </div>
            ))}

            <div className="mt-4 flex items-center gap-2 rounded-md border border-[color:var(--soc-medium)]/30 bg-[color:var(--soc-medium)]/5 p-3 text-[11px] text-muted-foreground">
              <Gauge className="h-3.5 w-3.5 shrink-0 text-[color:var(--soc-medium)]" />
              <span>
                Confidence values reflect the rule's inherent reliability, not the probability of an attack. All alerts require human verification within the authorized assessment scope.
              </span>
            </div>
          </div>
        </ScrollArea>
      </DialogContent>
    </Dialog>
  );
}
