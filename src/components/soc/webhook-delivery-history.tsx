"use client";

import { useState, useEffect, useCallback } from "react";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Button } from "@/components/ui/button";
import { api } from "@/lib/api-client";
import type { WebhookDelivery } from "@/lib/types";
import {
  History,
  CheckCircle2,
  XCircle,
  Clock,
  AlertTriangle,
  RefreshCw,
  ChevronDown,
  ChevronRight,
  Trash2,
} from "lucide-react";
import { toast } from "sonner";

interface WebhookDeliveryHistoryProps {
  webhookId: string | null;
  webhookName: string;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

const STATUS_CONFIG = {
  success: { color: "var(--soc-success)", icon: CheckCircle2, label: "Success" },
  failed: { color: "var(--soc-critical)", icon: XCircle, label: "Failed" },
  timeout: { color: "var(--soc-high)", icon: Clock, label: "Timeout" },
  error: { color: "var(--soc-critical)", icon: AlertTriangle, label: "Error" },
} as const;

export function WebhookDeliveryHistory({
  webhookId,
  webhookName,
  open,
  onOpenChange,
}: WebhookDeliveryHistoryProps) {
  const [deliveries, setDeliveries] = useState<WebhookDelivery[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [clearing, setClearing] = useState(false);
  const [expandedIds, setExpandedIds] = useState<Set<string>>(new Set());

  const fetchDeliveries = useCallback(async () => {
    if (!webhookId) return;
    setLoading(true);
    try {
      const res = await api.getWebhookDeliveries(webhookId, 50);
      setDeliveries(res.deliveries);
      setTotal(res.total);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to load deliveries");
    } finally {
      setLoading(false);
    }
  }, [webhookId]);

  useEffect(() => {
    if (open && webhookId) {
      fetchDeliveries();
    }
  }, [open, webhookId, fetchDeliveries]);

  const handleClear = useCallback(async () => {
    if (!webhookId) return;
    if (!window.confirm(`Clear all ${total} delivery records for "${webhookName}"? This cannot be undone.`)) return;
    setClearing(true);
    try {
      const res = await api.clearWebhookDeliveries(webhookId);
      toast.success(`Cleared ${res.deleted} delivery record(s)`);
      setDeliveries([]);
      setTotal(0);
      setExpandedIds(new Set());
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to clear deliveries");
    } finally {
      setClearing(false);
    }
  }, [webhookId, webhookName, total]);

  const toggleExpand = (id: string) => {
    setExpandedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const successCount = deliveries.filter((d) => d.status === "success").length;
  const failCount = deliveries.filter((d) => d.status !== "success").length;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[90vh] max-w-3xl overflow-hidden p-0 gap-0">
        <DialogHeader className="border-b border-border/60 px-5 py-4">
          <DialogTitle className="flex items-center gap-2 font-mono-data text-sm uppercase tracking-wider">
            <History className="h-4 w-4 text-[color:var(--soc-low)]" />
            Delivery History
          </DialogTitle>
          <DialogDescription className="text-xs">
            {webhookName} — {total} total deliveries · {successCount} succeeded · {failCount} failed
          </DialogDescription>
        </DialogHeader>

        <div className="flex items-center justify-between border-b border-border/40 bg-card/20 px-5 py-2">
          <span className="font-mono-data text-[10px] text-muted-foreground">
            Showing last {deliveries.length} of {total}
          </span>
          <div className="flex items-center gap-1.5">
            <Button
              size="sm"
              variant="ghost"
              className="h-7 gap-1.5 text-[11px]"
              onClick={fetchDeliveries}
              disabled={loading}
            >
              <RefreshCw className={`h-3 w-3 ${loading ? "animate-spin" : ""}`} />
              Refresh
            </Button>
            {deliveries.length > 0 && (
              <Button
                size="sm"
                variant="ghost"
                className="h-7 gap-1.5 text-[11px] text-[color:var(--soc-critical)] hover:text-[color:var(--soc-critical)]"
                onClick={handleClear}
                disabled={clearing}
                title="Clear all delivery history for this webhook"
              >
                {clearing ? (
                  <RefreshCw className="h-3 w-3 animate-spin" />
                ) : (
                  <Trash2 className="h-3 w-3" />
                )}
                Clear All
              </Button>
            )}
          </div>
        </div>

        <ScrollArea className="h-[calc(90vh-160px)] soc-scrollbar">
          <div className="p-3">
            {deliveries.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-12">
                <History className="h-8 w-8 text-muted-foreground/30" />
                <p className="mt-2 font-mono-data text-[10px] uppercase tracking-wider text-muted-foreground/60">
                  No deliveries yet
                </p>
                <p className="mt-1 text-[10px] text-muted-foreground">
                  Deliveries will appear here when alerts trigger this webhook.
                </p>
              </div>
            ) : (
              <div className="space-y-1.5">
                {deliveries.map((d) => {
                  const cfg = STATUS_CONFIG[d.status as keyof typeof STATUS_CONFIG] ?? STATUS_CONFIG.error;
                  const Icon = cfg.icon;
                  const isExpanded = expandedIds.has(d.id);
                  return (
                    <div
                      key={d.id}
                      className="rounded-md border border-border/40 bg-card/30 overflow-hidden"
                    >
                      <button
                        type="button"
                        onClick={() => toggleExpand(d.id)}
                        className="flex w-full items-center gap-2 px-3 py-2 text-left transition-colors hover:bg-accent/20"
                      >
                        <Icon className="h-3.5 w-3.5 shrink-0" style={{ color: cfg.color }} />
                        <span
                          className="rounded-sm border px-1.5 py-0.5 font-mono-data text-[9px] font-bold uppercase tracking-wider shrink-0"
                          style={{
                            color: cfg.color,
                            borderColor: `color-mix(in oklch, ${cfg.color} 40%, transparent)`,
                            backgroundColor: `color-mix(in oklch, ${cfg.color} 12%, transparent)`,
                          }}
                        >
                          {cfg.label}
                        </span>
                        {d.statusCode != null && (
                          <span className="font-mono-data text-[10px] text-muted-foreground shrink-0">
                            {d.statusCode}
                          </span>
                        )}
                        <span className="min-w-0 flex-1 truncate font-mono-data text-[10px] text-foreground/70">
                          {d.alertId ?? d.eventType}
                        </span>
                        {d.latencyMs != null && (
                          <span className="font-mono-data text-[9px] text-muted-foreground shrink-0">
                            {d.latencyMs}ms
                          </span>
                        )}
                        <span className="font-mono-data text-[9px] text-muted-foreground shrink-0">
                          {new Date(d.calledAt).toLocaleTimeString("en-US", { hour12: false })}
                        </span>
                        {isExpanded ? (
                          <ChevronDown className="h-3 w-3 shrink-0 text-muted-foreground" />
                        ) : (
                          <ChevronRight className="h-3 w-3 shrink-0 text-muted-foreground" />
                        )}
                      </button>

                      {isExpanded && (
                        <div className="border-t border-border/30 bg-background/30 px-3 py-2.5 space-y-2">
                          {d.errorMessage && (
                            <div>
                              <div className="font-mono-data text-[9px] uppercase tracking-wider text-[color:var(--soc-critical)]">
                                Error
                              </div>
                              <pre className="mt-0.5 rounded bg-[color:var(--soc-critical)]/5 p-2 font-mono-data text-[10px] text-[color:var(--soc-critical)]/80 whitespace-pre-wrap break-words">
                                {d.errorMessage}
                              </pre>
                            </div>
                          )}
                          {d.responseExcerpt && (
                            <div>
                              <div className="font-mono-data text-[9px] uppercase tracking-wider text-muted-foreground">
                                Response
                              </div>
                              <pre className="mt-0.5 rounded bg-muted/30 p-2 font-mono-data text-[10px] text-foreground/70 whitespace-pre-wrap break-words max-h-32 overflow-y-auto soc-scrollbar">
                                {d.responseExcerpt}
                              </pre>
                            </div>
                          )}
                          <div>
                            <div className="font-mono-data text-[9px] uppercase tracking-wider text-muted-foreground">
                              Payload
                            </div>
                            <pre className="mt-0.5 rounded bg-muted/30 p-2 font-mono-data text-[10px] text-foreground/70 whitespace-pre-wrap break-words max-h-40 overflow-y-auto soc-scrollbar">
                              {(() => {
                                try {
                                  return JSON.stringify(JSON.parse(d.payload), null, 2);
                                } catch {
                                  return d.payload;
                                }
                              })()}
                            </pre>
                          </div>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </ScrollArea>
      </DialogContent>
    </Dialog>
  );
}
