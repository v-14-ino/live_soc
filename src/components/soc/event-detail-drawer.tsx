"use client";

import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetDescription,
} from "@/components/ui/sheet";
import { ScrollArea } from "@/components/ui/scroll-area";
import { SeverityBadge } from "@/components/soc/severity-badge";
import type { SecurityEvent } from "@/lib/types";
import {
  Clock,
  ArrowRight,
  Network,
  Tag,
  FileText,
  Info,
  ShieldAlert,
  Hash,
} from "lucide-react";

interface EventDetailDrawerProps {
  event: SecurityEvent | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  relatedEvents?: SecurityEvent[];
}

function FieldRow({
  icon: Icon,
  label,
  value,
  mono = true,
}: {
  icon: typeof Clock;
  label: string;
  value: string | number | null | undefined;
  mono?: boolean;
}) {
  return (
    <div className="flex items-center justify-between gap-3 border-b border-border/40 py-2 last:border-0">
      <div className="flex items-center gap-2 text-[11px] text-muted-foreground">
        <Icon className="h-3.5 w-3.5" />
        <span className="uppercase tracking-wider">{label}</span>
      </div>
      <div className={`text-sm text-foreground ${mono ? "font-mono-data" : ""}`}>
        {value ?? "—"}
      </div>
    </div>
  );
}

export function EventDetailDrawer({
  event,
  open,
  onOpenChange,
  relatedEvents = [],
}: EventDetailDrawerProps) {
  if (!event) {
    return (
      <Sheet open={open} onOpenChange={onOpenChange}>
        <SheetContent side="right" className="w-full sm:max-w-md p-0" />
      </Sheet>
    );
  }

  const time = new Date(event.timestamp);
  const timeStr = time.toLocaleTimeString("en-US", { hour12: false });
  const dateStr = time.toLocaleDateString("en-US", { year: "numeric", month: "short", day: "numeric" });

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent side="right" className="w-full overflow-hidden p-0 sm:max-w-md gap-0">
        <SheetHeader className="border-b border-border/60 px-5 py-4">
          <SheetTitle className="flex items-center gap-2 font-mono-data text-sm">
            <span className="text-[color:var(--soc-low)]">{event.eventId}</span>
            <SeverityBadge severity={event.severity} size="sm" />
            {event.isDemo && (
              <span className="rounded-sm border border-[color:var(--soc-medium)]/40 bg-[color:var(--soc-medium)]/10 px-1.5 py-0.5 font-mono-data text-[9px] font-bold uppercase tracking-wider text-[color:var(--soc-medium)]">
                Demo
              </span>
            )}
          </SheetTitle>
          <SheetDescription className="text-xs">
            Security event detail — observed activity from {event.source} telemetry source
          </SheetDescription>
        </SheetHeader>

        <ScrollArea className="h-[calc(100vh-80px)] soc-scrollbar">
          <div className="space-y-4 p-5">
            {/* Event message */}
            <div className="rounded-lg border border-border/60 bg-card/40 p-3">
              <div className="mb-1.5 flex items-center gap-1.5 font-mono-data text-[9px] uppercase tracking-wider text-muted-foreground">
                <FileText className="h-3 w-3" />
                Event Message
              </div>
              <p className="text-sm text-foreground leading-relaxed">
                {event.message}
              </p>
            </div>

            {/* Connection info */}
            <div className="rounded-lg border border-border/60 bg-card/40 p-4">
              <div className="mb-3 flex items-center gap-1.5 font-mono-data text-[9px] uppercase tracking-wider text-muted-foreground">
                <Network className="h-3 w-3" />
                Connection
              </div>
              <div className="flex items-center justify-center gap-3 py-2">
                <div className="flex-1 text-center">
                  <div className="font-mono-data text-[9px] uppercase tracking-wider text-muted-foreground">Source</div>
                  <div className="mt-1 font-mono-data text-sm font-semibold text-foreground">
                    {event.sourceIp ?? "—"}
                  </div>
                  {event.sourcePort != null && (
                    <div className="font-mono-data text-[10px] text-muted-foreground">
                      :{event.sourcePort}
                    </div>
                  )}
                </div>
                <ArrowRight className="h-4 w-4 shrink-0 text-[color:var(--soc-low)]" />
                <div className="flex-1 text-center">
                  <div className="font-mono-data text-[9px] uppercase tracking-wider text-muted-foreground">Destination</div>
                  <div className="mt-1 font-mono-data text-sm font-semibold text-foreground">
                    {event.destIp ?? "—"}
                  </div>
                  {event.destPort != null && (
                    <div className="font-mono-data text-[10px] text-muted-foreground">
                      :{event.destPort}
                    </div>
                  )}
                </div>
              </div>
            </div>

            {/* Metadata */}
            <div className="rounded-lg border border-border/60 bg-card/40 p-4">
              <div className="mb-2 flex items-center gap-1.5 font-mono-data text-[9px] uppercase tracking-wider text-muted-foreground">
                <Info className="h-3 w-3" />
                Metadata
              </div>
              <FieldRow icon={Clock} label="Time" value={`${dateStr} ${timeStr}`} />
              <FieldRow icon={Tag} label="Type" value={event.eventType} />
              <FieldRow icon={Hash} label="Protocol" value={(event.protocol ?? "—").toUpperCase()} />
              <FieldRow icon={ShieldAlert} label="Source Collector" value={event.source} />
              <FieldRow icon={Info} label="Status" value={event.status} />
              <FieldRow icon={Hash} label="Event ID" value={event.eventId} />
            </div>

            {/* Raw data */}
            {event.raw && Object.keys(event.raw).length > 0 && (
              <div className="rounded-lg border border-border/60 bg-card/40 p-4">
                <div className="mb-2 flex items-center gap-1.5 font-mono-data text-[9px] uppercase tracking-wider text-muted-foreground">
                  <FileText className="h-3 w-3" />
                  Raw Telemetry Data
                </div>
                <pre className="overflow-x-auto rounded-md bg-background/50 p-3 font-mono-data text-[11px] text-foreground/80 soc-scrollbar">
                  {JSON.stringify(event.raw, null, 2)}
                </pre>
              </div>
            )}

            {/* Related events (same source or same dest port) */}
            {relatedEvents.length > 0 && (
              <div className="rounded-lg border border-border/60 bg-card/40 p-4">
                <div className="mb-2 flex items-center justify-between">
                  <div className="flex items-center gap-1.5 font-mono-data text-[9px] uppercase tracking-wider text-muted-foreground">
                    <Network className="h-3 w-3" />
                    Related Activity
                  </div>
                  <span className="font-mono-data text-[10px] text-muted-foreground">
                    {relatedEvents.length} event{relatedEvents.length !== 1 ? "s" : ""}
                  </span>
                </div>
                <div className="space-y-1.5">
                  {relatedEvents.slice(0, 20).map((re) => (
                    <div
                      key={re.eventId}
                      className="flex items-center gap-2 rounded-md border border-border/40 bg-background/30 px-2.5 py-1.5"
                    >
                      <span className="font-mono-data text-[10px] text-muted-foreground shrink-0">
                        {new Date(re.timestamp).toLocaleTimeString("en-US", { hour12: false })}
                      </span>
                      <SeverityBadge severity={re.severity} size="sm" />
                      <span className="truncate text-[11px] text-foreground/70">
                        {re.message}
                      </span>
                    </div>
                  ))}
                  {relatedEvents.length > 20 && (
                    <div className="text-center font-mono-data text-[10px] text-muted-foreground py-1">
                      +{relatedEvents.length - 20} more
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* Disclaimer */}
            <div className="rounded-md border border-[color:var(--soc-medium)]/30 bg-[color:var(--soc-medium)]/5 p-2.5 text-[10px] text-muted-foreground leading-relaxed">
              This event represents observed activity within an authorized assessment scope. It does not confirm an attack. Correlation with other events is required for scenario analysis.
            </div>
          </div>
        </ScrollArea>
      </SheetContent>
    </Sheet>
  );
}
