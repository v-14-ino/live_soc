"use client";

import { useState, useEffect, useCallback } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog";
import { api } from "@/lib/api-client";
import { SeverityBadge } from "@/components/soc/severity-badge";
import type { WebhookConfig, WebhookInput, Severity } from "@/lib/types";
import {
  Webhook,
  Plus,
  Trash2,
  Pencil,
  Send,
  CheckCircle2,
  XCircle,
  Loader2,
} from "lucide-react";
import { toast } from "sonner";

const ALL_SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

export function WebhooksPanel() {
  const [webhooks, setWebhooks] = useState<WebhookConfig[]>([]);
  const [loading, setLoading] = useState(true);
  const [showEditor, setShowEditor] = useState(false);
  const [editingWebhook, setEditingWebhook] = useState<WebhookConfig | null>(null);
  const [testing, setTesting] = useState<string | null>(null);

  const fetchWebhooks = useCallback(async () => {
    setLoading(true);
    try {
      const res = await api.getWebhooks();
      setWebhooks(res.webhooks);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to load webhooks");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchWebhooks();
  }, [fetchWebhooks]);

  const handleDelete = useCallback(async (id: string, name: string) => {
    if (!window.confirm(`Delete webhook "${name}"?`)) return;
    try {
      await api.deleteWebhook(id);
      setWebhooks((prev) => prev.filter((w) => w.id !== id));
      toast.success(`Webhook "${name}" deleted`);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to delete webhook");
    }
  }, []);

  const handleToggle = useCallback(async (wh: WebhookConfig) => {
    try {
      await api.updateWebhook(wh.id, { enabled: !wh.enabled });
      setWebhooks((prev) =>
        prev.map((w) => (w.id === wh.id ? { ...w, enabled: !w.enabled } : w)),
      );
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to toggle webhook");
    }
  }, []);

  const handleTest = useCallback(async (wh: WebhookConfig) => {
    setTesting(wh.id);
    try {
      const res = await api.testWebhook(wh.id);
      if (res.ok) {
        toast.success(`Test delivered: ${res.message}`);
      } else {
        toast.error(`Test failed: ${res.message}`);
      }
      await fetchWebhooks();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to test webhook");
    } finally {
      setTesting(null);
    }
  }, [fetchWebhooks]);

  const handleEdit = useCallback((wh: WebhookConfig) => {
    setEditingWebhook(wh);
    setShowEditor(true);
  }, []);

  const handleCreate = useCallback(() => {
    setEditingWebhook(null);
    setShowEditor(true);
  }, []);

  const handleSaved = useCallback((wh: WebhookConfig) => {
    setWebhooks((prev) => {
      const idx = prev.findIndex((w) => w.id === wh.id);
      if (idx >= 0) {
        const next = [...prev];
        next[idx] = wh;
        return next;
      }
      return [wh, ...prev];
    });
    setShowEditor(false);
    setEditingWebhook(null);
  }, []);

  const enabledCount = webhooks.filter((w) => w.enabled).length;

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <div>
          <h4 className="flex items-center gap-1.5 font-mono-data text-[11px] uppercase tracking-wider text-foreground">
            <Webhook className="h-3.5 w-3.5 text-[color:var(--soc-low)]" />
            Webhook Notifications
          </h4>
          <p className="mt-0.5 text-[10px] text-muted-foreground">
            {enabledCount} of {webhooks.length} enabled · fires on matching severity alerts
          </p>
        </div>
        <Button onClick={handleCreate} size="sm" variant="outline" className="gap-1.5 text-[11px]">
          <Plus className="h-3 w-3" />
          Add Webhook
        </Button>
      </div>

      {loading ? (
        <div className="space-y-2">
          {[1, 2].map((i) => (
            <div key={i} className="h-20 animate-pulse rounded-md bg-muted/30" />
          ))}
        </div>
      ) : webhooks.length === 0 ? (
        <div className="rounded-md border border-dashed border-border/50 bg-card/20 px-4 py-6 text-center">
          <Webhook className="mx-auto h-6 w-6 text-muted-foreground/30" />
          <p className="mt-2 font-mono-data text-[10px] uppercase tracking-wider text-muted-foreground/60">
            No webhooks configured
          </p>
          <p className="mt-1 text-[10px] text-muted-foreground">
            Receive POST notifications when high-severity alerts fire.
          </p>
        </div>
      ) : (
        <div className="space-y-2">
          {webhooks.map((wh) => (
            <div
              key={wh.id}
              className={`rounded-md border bg-card/30 p-3 transition-opacity ${
                wh.enabled ? "border-border/60 opacity-100" : "border-border/40 opacity-60"
              }`}
            >
              <div className="flex items-start justify-between gap-2">
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-semibold text-foreground">{wh.name}</span>
                    {wh.enabled ? (
                      <CheckCircle2 className="h-3 w-3 text-[color:var(--soc-success)]" />
                    ) : (
                      <XCircle className="h-3 w-3 text-muted-foreground" />
                    )}
                  </div>
                  <div className="mt-0.5 truncate font-mono-data text-[10px] text-muted-foreground" title={wh.url}>
                    {wh.url}
                  </div>
                  <div className="mt-1 flex flex-wrap items-center gap-1">
                    {wh.severities.map((s) => (
                      <SeverityBadge key={s} severity={s as Severity} size="sm" />
                    ))}
                    <span className="font-mono-data text-[9px] text-muted-foreground">
                      · cooldown {wh.cooldownSec}s
                    </span>
                  </div>
                  <div className="mt-1 flex items-center gap-3 font-mono-data text-[9px] text-muted-foreground">
                    <span className="text-[color:var(--soc-success)]">{wh.callCount} sent</span>
                    {wh.failCount > 0 && (
                      <span className="text-[color:var(--soc-critical)]">{wh.failCount} failed</span>
                    )}
                    {wh.lastCalled && (
                      <span>· last: {new Date(wh.lastCalled).toLocaleTimeString("en-US", { hour12: false })}</span>
                    )}
                    {wh.lastError && (
                      <span className="truncate text-[color:var(--soc-critical)]/70" title={wh.lastError}>
                        · {wh.lastError}
                      </span>
                    )}
                  </div>
                </div>
                <div className="flex shrink-0 items-center gap-1">
                  <Switch checked={wh.enabled} onCheckedChange={() => handleToggle(wh)} />
                  <Button
                    size="sm"
                    variant="ghost"
                    className="h-7 w-7 p-0"
                    onClick={() => handleTest(wh)}
                    disabled={testing === wh.id}
                    title="Send test payload"
                  >
                    {testing === wh.id ? (
                      <Loader2 className="h-3 w-3 animate-spin" />
                    ) : (
                      <Send className="h-3 w-3" />
                    )}
                  </Button>
                  <Button
                    size="sm"
                    variant="ghost"
                    className="h-7 w-7 p-0"
                    onClick={() => handleEdit(wh)}
                    title="Edit webhook"
                  >
                    <Pencil className="h-3 w-3" />
                  </Button>
                  <Button
                    size="sm"
                    variant="ghost"
                    className="h-7 w-7 p-0 text-[color:var(--soc-critical)]"
                    onClick={() => handleDelete(wh.id, wh.name)}
                    title="Delete webhook"
                  >
                    <Trash2 className="h-3 w-3" />
                  </Button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {showEditor && (
        <WebhookEditor
          webhook={editingWebhook}
          onClose={() => {
            setShowEditor(false);
            setEditingWebhook(null);
          }}
          onSaved={handleSaved}
        />
      )}
    </div>
  );
}

// ============================================================
// Webhook Editor
// ============================================================

interface WebhookEditorProps {
  webhook: WebhookConfig | null;
  onClose: () => void;
  onSaved: (wh: WebhookConfig) => void;
}

function WebhookEditor({ webhook, onClose, onSaved }: WebhookEditorProps) {
  const [name, setName] = useState(webhook?.name ?? "");
  const [url, setUrl] = useState(webhook?.url ?? "");
  const [enabled, setEnabled] = useState(webhook?.enabled ?? true);
  const [severities, setSeverities] = useState<Severity[]>(
    webhook?.severities as Severity[] ?? ["critical", "high"],
  );
  const [secret, setSecret] = useState(webhook?.secret ?? "");
  const [cooldownSec, setCooldownSec] = useState(webhook?.cooldownSec ?? 10);
  const [saving, setSaving] = useState(false);

  const toggleSeverity = (s: Severity) => {
    setSeverities((prev) =>
      prev.includes(s) ? prev.filter((x) => x !== s) : [...prev, s],
    );
  };

  const handleSave = async () => {
    if (!name.trim()) {
      toast.error("Name is required");
      return;
    }
    if (!url.trim() || !url.startsWith("http")) {
      toast.error("Valid URL is required (must start with http)");
      return;
    }
    if (severities.length === 0) {
      toast.error("Select at least one severity");
      return;
    }

    setSaving(true);
    try {
      const input: WebhookInput = {
        name: name.trim(),
        url: url.trim(),
        enabled,
        severities,
        secret: secret.trim() || undefined,
        cooldownSec,
      };
      let saved: WebhookConfig;
      if (webhook) {
        const res = await api.updateWebhook(webhook.id, input);
        saved = res.webhook;
        toast.success(`Webhook "${saved.name}" updated`);
      } else {
        const res = await api.createWebhook(input);
        saved = res.webhook;
        toast.success(`Webhook "${saved.name}" created`);
      }
      onSaved(saved);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to save webhook");
    } finally {
      setSaving(false);
    }
  };

  return (
    <Dialog open={true} onOpenChange={() => onClose()}>
      <DialogContent className="max-w-lg p-0 gap-0 overflow-hidden">
        <DialogHeader className="border-b border-border/60 px-5 py-4">
          <DialogTitle className="flex items-center gap-2 font-mono-data text-sm uppercase tracking-wider">
            <Webhook className="h-4 w-4 text-[color:var(--soc-low)]" />
            {webhook ? "Edit Webhook" : "New Webhook"}
          </DialogTitle>
          <DialogDescription className="text-xs">
            Configure a webhook endpoint to receive POST notifications when alerts match the selected severities.
          </DialogDescription>
        </DialogHeader>

        <div className="soc-scrollbar max-h-[calc(92vh-140px)] overflow-y-auto p-5">
          <div className="space-y-4">
            <div className="space-y-1.5">
              <Label className="font-mono-data text-[10px] uppercase tracking-wider">Name</Label>
              <Input
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="e.g. SOC Slack Alert Channel"
                className="text-xs"
              />
            </div>

            <div className="space-y-1.5">
              <Label className="font-mono-data text-[10px] uppercase tracking-wider">Webhook URL</Label>
              <Input
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="https://hooks.slack.com/services/... or https://your-endpoint/webhook"
                className="font-mono-data text-xs"
              />
            </div>

            <div className="space-y-1.5">
              <Label className="font-mono-data text-[10px] uppercase tracking-wider">Trigger Severities</Label>
              <div className="flex flex-wrap gap-1.5">
                {ALL_SEVERITIES.map((s) => {
                  const selected = severities.includes(s);
                  return (
                    <button
                      key={s}
                      type="button"
                      onClick={() => toggleSeverity(s)}
                      className={`rounded-md border px-2 py-1 font-mono-data text-[10px] uppercase tracking-wider transition-colors ${
                        selected
                          ? "border-[color:var(--soc-low)]/40 bg-[color:var(--soc-low)]/10 text-[color:var(--soc-low)]"
                          : "border-border/40 bg-background/30 text-muted-foreground"
                      }`}
                    >
                      {s}
                    </button>
                  );
                })}
              </div>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <Label className="font-mono-data text-[10px] uppercase tracking-wider">Cooldown (sec)</Label>
                <Input
                  type="number"
                  min={1}
                  max={3600}
                  value={cooldownSec}
                  onChange={(e) => setCooldownSec(Math.max(1, Number(e.target.value)))}
                  className="font-mono-data text-xs"
                />
              </div>
              <div className="space-y-1.5">
                <Label className="font-mono-data text-[10px] uppercase tracking-wider">Secret (optional, HMAC)</Label>
                <Input
                  value={secret}
                  onChange={(e) => setSecret(e.target.value)}
                  placeholder="for signature verification"
                  className="font-mono-data text-xs"
                  type="password"
                />
              </div>
            </div>

            <div className="flex items-center justify-between rounded-md border border-border/40 bg-background/30 p-3">
              <div>
                <span className="text-xs font-medium">Enabled</span>
                <p className="text-[10px] text-muted-foreground">When disabled, no notifications are sent.</p>
              </div>
              <Switch checked={enabled} onCheckedChange={setEnabled} />
            </div>

            <div className="rounded-md border border-[color:var(--soc-medium)]/30 bg-[color:var(--soc-medium)]/5 p-3 text-[10px] text-muted-foreground leading-relaxed">
              <strong className="text-foreground">Payload format:</strong> JSON POST with <code className="font-mono-data">{"{ platform, event, alert: { alertId, ruleId, ruleName, severity, message, ... } }"}</code>. If a secret is set, an <code className="font-mono-data">X-LiveSOC-Signature: sha256=...</code> header is included (HMAC-SHA256 of the body).
            </div>
          </div>
        </div>

        <DialogFooter className="border-t border-border/60 bg-card/30 px-5 py-3">
          <Button variant="outline" size="sm" onClick={onClose}>Cancel</Button>
          <Button size="sm" onClick={handleSave} disabled={saving} className="gap-1.5">
            {saving ? (
              <>
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
                Saving…
              </>
            ) : (
              <>
                <Webhook className="h-3.5 w-3.5" />
                {webhook ? "Update Webhook" : "Create Webhook"}
              </>
            )}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
