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
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { api } from "@/lib/api-client";
import {
  MonitorSmartphone,
  Plus,
  KeyRound,
  Power,
  Copy,
  Check,
  Loader2,
  Trash2,
  RefreshCw,
} from "lucide-react";
import { toast } from "sonner";

// ============================================================
// Agent Management Panel (Phase B)
//
// Displays registered agents with status, enable/disable,
// API key rotation, and registration dialog.
// ============================================================

interface AgentInfo {
  id: string;
  agentId: string;
  name: string;
  hostname: string | null;
  os: string | null;
  version: string | null;
  ip: string | null;
  status: string;
  enabled: boolean;
  lastHeartbeat: string | null;
  hasApiKey: boolean;
  createdAt: string;
  updatedAt: string;
}

const STATUS_CONFIG: Record<string, { color: string; label: string }> = {
  ONLINE: { color: "var(--soc-success)", label: "Online" },
  DEGRADED: { color: "var(--soc-medium)", label: "Degraded" },
  OFFLINE: { color: "var(--soc-critical)", label: "Offline" },
};

const OS_ICON: Record<string, string> = {
  Linux: "🐧",
  Windows: "🪟",
};

export function AgentManagementPanel() {
  const [agents, setAgents] = useState<AgentInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [showRegister, setShowRegister] = useState(false);
  const [newApiKey, setNewApiKey] = useState<string | null>(null);
  const [rotatingId, setRotatingId] = useState<string | null>(null);
  const [confirmRotate, setConfirmRotate] = useState<string | null>(null);

  const fetchAgents = useCallback(async () => {
    try {
      const res = await api.getAgents();
      setAgents(res.agents as AgentInfo[]);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to load agents");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchAgents();
    // Poll every 15s for status updates
    const id = setInterval(fetchAgents, 15000);
    return () => clearInterval(id);
  }, [fetchAgents]);

  const handleToggle = useCallback(async (agent: AgentInfo) => {
    try {
      const res = await api.updateAgent(agent.agentId, { enabled: !agent.enabled });
      setAgents((prev) => prev.map((a) => (a.agentId === agent.agentId ? res.agent : a)));
      toast.success(`Agent ${agent.enabled ? "disabled" : "enabled"}`);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to toggle agent");
    }
  }, []);

  const handleRotateKey = useCallback(async (agentId: string) => {
    setRotatingId(agentId);
    setConfirmRotate(null);
    try {
      const res = await api.rotateAgentKey(agentId);
      setNewApiKey(res.apiKey);
      toast.success("API key rotated. Old key is now invalid.");
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to rotate key");
    } finally {
      setRotatingId(null);
    }
  }, []);

  const handleRegistered = useCallback((agent: AgentInfo, apiKey: string) => {
    setAgents((prev) => [agent, ...prev]);
    setNewApiKey(apiKey);
    setShowRegister(false);
  }, []);

  const onlineCount = agents.filter((a) => a.status === "ONLINE").length;

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <div>
          <h4 className="flex items-center gap-1.5 font-mono-data text-[11px] uppercase tracking-wider text-foreground">
            <MonitorSmartphone className="h-3.5 w-3.5 text-[color:var(--soc-low)]" />
            Agents
          </h4>
          <p className="mt-0.5 text-[10px] text-muted-foreground">
            {onlineCount} of {agents.length} online · registered telemetry agents
          </p>
        </div>
        <Button onClick={() => setShowRegister(true)} size="sm" variant="outline" className="gap-1.5 text-[11px]">
          <Plus className="h-3 w-3" />
          Register
        </Button>
      </div>

      {loading ? (
        <div className="space-y-2">
          {[1, 2].map((i) => (
            <div key={i} className="h-16 animate-pulse rounded-md bg-muted/30" />
          ))}
        </div>
      ) : agents.length === 0 ? (
        <div className="rounded-md border border-dashed border-border/50 bg-card/20 px-4 py-6 text-center">
          <MonitorSmartphone className="mx-auto h-6 w-6 text-muted-foreground/30" />
          <p className="mt-2 font-mono-data text-[10px] uppercase tracking-wider text-muted-foreground/60">
            No agents registered
          </p>
          <p className="mt-1 text-[10px] text-muted-foreground">
            Register a Linux or Windows agent to start collecting real telemetry.
          </p>
        </div>
      ) : (
        <div className="space-y-2">
          {agents.map((agent) => {
            const statusCfg = STATUS_CONFIG[agent.status] ?? STATUS_CONFIG.OFFLINE;
            const osIcon = agent.os ? OS_ICON[agent.os] ?? "💻" : "💻";
            return (
              <div
                key={agent.id}
                className={`rounded-md border bg-card/30 p-3 transition-opacity ${
                  agent.enabled ? "border-border/60 opacity-100" : "border-border/40 opacity-60"
                }`}
              >
                <div className="flex items-start justify-between gap-2">
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <span className="text-sm">{osIcon}</span>
                      <span className="text-xs font-semibold text-foreground">{agent.name || agent.agentId}</span>
                      <span
                        className="inline-flex items-center gap-1 rounded-sm border px-1.5 py-0.5 font-mono-data text-[9px] font-bold uppercase tracking-wider"
                        style={{
                          color: statusCfg.color,
                          borderColor: `color-mix(in oklch, ${statusCfg.color} 40%, transparent)`,
                          backgroundColor: `color-mix(in oklch, ${statusCfg.color} 12%, transparent)`,
                        }}
                      >
                        <span
                          className="inline-block h-1.5 w-1.5 rounded-full"
                          style={{ backgroundColor: statusCfg.color }}
                        />
                        {statusCfg.label}
                      </span>
                      {!agent.enabled && (
                        <span className="rounded-sm border border-border/40 px-1 py-0.5 font-mono-data text-[8px] uppercase text-muted-foreground">
                          Disabled
                        </span>
                      )}
                    </div>
                    <div className="mt-0.5 flex flex-wrap items-center gap-x-2 gap-y-0.5 font-mono-data text-[9px] text-muted-foreground">
                      <span>{agent.agentId}</span>
                      {agent.hostname && (<><span className="text-muted-foreground/40">·</span><span>{agent.hostname}</span></>)}
                      {agent.os && (<><span className="text-muted-foreground/40">·</span><span>{agent.os}</span></>)}
                      {agent.ip && (<><span className="text-muted-foreground/40">·</span><span>{agent.ip}</span></>)}
                      {agent.version && (<><span className="text-muted-foreground/40">·</span><span>v{agent.version}</span></>)}
                    </div>
                    {agent.lastHeartbeat && (
                      <div className="mt-0.5 font-mono-data text-[8px] text-muted-foreground/60">
                        Last heartbeat: {new Date(agent.lastHeartbeat).toLocaleString("en-US")}
                      </div>
                    )}
                  </div>
                  <div className="flex shrink-0 items-center gap-1">
                    <Switch
                      checked={agent.enabled}
                      onCheckedChange={() => handleToggle(agent)}
                      title={agent.enabled ? "Disable agent" : "Enable agent"}
                    />
                    <Button
                      size="sm"
                      variant="ghost"
                      className="h-7 w-7 p-0"
                      onClick={() => setConfirmRotate(agent.agentId)}
                      disabled={rotatingId === agent.agentId}
                      title="Rotate API key"
                    >
                      {rotatingId === agent.agentId ? (
                        <Loader2 className="h-3 w-3 animate-spin" />
                      ) : (
                        <KeyRound className="h-3 w-3" />
                      )}
                    </Button>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Registration dialog */}
      {showRegister && (
        <RegisterAgentDialog
          onClose={() => setShowRegister(false)}
          onRegistered={handleRegistered}
        />
      )}

      {/* API key display (after registration or rotation) */}
      {newApiKey && (
        <ApiKeyDisplayDialog apiKey={newApiKey} onClose={() => setNewApiKey(null)} />
      )}

      {/* Rotate key confirmation */}
      <AlertDialog open={!!confirmRotate} onOpenChange={(o) => { if (!o) setConfirmRotate(null); }}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Rotate API Key?</AlertDialogTitle>
            <AlertDialogDescription>
              This will generate a new API key and invalidate the old one. The agent must be updated with the new key to continue sending telemetry. The new key will be shown only once.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => confirmRotate && handleRotateKey(confirmRotate)}
              className="bg-[color:var(--soc-medium)] text-white hover:bg-[color:var(--soc-medium)]/80"
            >
              <KeyRound className="h-3.5 w-3.5 mr-1.5" />
              Rotate Key
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}

// ============================================================
// Registration Dialog
// ============================================================

function RegisterAgentDialog({
  onClose,
  onRegistered,
}: {
  onClose: () => void;
  onRegistered: (agent: AgentInfo, apiKey: string) => void;
}) {
  const [agentId, setAgentId] = useState("");
  const [name, setName] = useState("");
  const [hostname, setHostname] = useState("");
  const [os, setOs] = useState("Linux");
  const [saving, setSaving] = useState(false);

  const handleRegister = async () => {
    if (!agentId.trim()) {
      toast.error("Agent ID is required");
      return;
    }
    setSaving(true);
    try {
      const res = await api.registerAgent({
        agentId: agentId.trim(),
        name: name.trim() || agentId.trim(),
        hostname: hostname.trim() || undefined,
        os: os || undefined,
      });
      onRegistered({
        id: "",
        agentId: res.agentId,
        name: name.trim() || agentId.trim(),
        hostname: hostname.trim() || null,
        os: os || null,
        version: null,
        ip: null,
        status: "OFFLINE",
        enabled: true,
        lastHeartbeat: null,
        hasApiKey: true,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      }, res.apiKey);
      toast.success(`Agent "${agentId}" registered`);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to register agent");
    } finally {
      setSaving(false);
    }
  };

  return (
    <Dialog open={true} onOpenChange={() => onClose()}>
      <DialogContent className="max-w-md p-0 gap-0 overflow-hidden">
        <DialogHeader className="border-b border-border/60 px-5 py-4">
          <DialogTitle className="flex items-center gap-2 font-mono-data text-sm uppercase tracking-wider">
            <Plus className="h-4 w-4 text-[color:var(--soc-low)]" />
            Register Agent
          </DialogTitle>
          <DialogDescription className="text-xs">
            Register a new telemetry agent. An API key will be generated — store it securely.
          </DialogDescription>
        </DialogHeader>
        <div className="p-5 space-y-3">
          <div className="space-y-1.5">
            <Label className="font-mono-data text-[10px] uppercase tracking-wider">Agent ID *</Label>
            <Input
              value={agentId}
              onChange={(e) => setAgentId(e.target.value)}
              placeholder="e.g. agent-linux-001 or agent-win-01"
              className="font-mono-data text-xs"
            />
          </div>
          <div className="space-y-1.5">
            <Label className="font-mono-data text-[10px] uppercase tracking-wider">Display Name</Label>
            <Input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g. Lab Linux Agent"
              className="text-xs"
            />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1.5">
              <Label className="font-mono-data text-[10px] uppercase tracking-wider">Hostname</Label>
              <Input
                value={hostname}
                onChange={(e) => setHostname(e.target.value)}
                placeholder="e.g. lab-linux-01"
                className="text-xs"
              />
            </div>
            <div className="space-y-1.5">
              <Label className="font-mono-data text-[10px] uppercase tracking-wider">OS</Label>
              <select
                value={os}
                onChange={(e) => setOs(e.target.value)}
                className="flex h-9 w-full rounded-md border border-input bg-background px-3 py-1 text-xs"
              >
                <option value="Linux">Linux 🐧</option>
                <option value="Windows">Windows 🪟</option>
                <option value="macOS">macOS</option>
                <option value="Other">Other</option>
              </select>
            </div>
          </div>
        </div>
        <DialogFooter className="border-t border-border/60 bg-card/30 px-5 py-3">
          <Button variant="outline" size="sm" onClick={onClose}>Cancel</Button>
          <Button size="sm" onClick={handleRegister} disabled={saving} className="gap-1.5">
            {saving ? (
              <><Loader2 className="h-3.5 w-3.5 animate-spin" /> Registering…</>
            ) : (
              <><Plus className="h-3.5 w-3.5" /> Register</>
            )}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ============================================================
// API Key Display Dialog (shown once after registration/rotation)
// ============================================================

function ApiKeyDisplayDialog({ apiKey, onClose }: { apiKey: string; onClose: () => void }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(apiKey);
    setCopied(true);
    toast.success("API key copied to clipboard");
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <Dialog open={true} onOpenChange={() => onClose()}>
      <DialogContent className="max-w-lg p-0 gap-0 overflow-hidden">
        <DialogHeader className="border-b border-border/60 px-5 py-4">
          <DialogTitle className="flex items-center gap-2 font-mono-data text-sm uppercase tracking-wider">
            <KeyRound className="h-4 w-4 text-[color:var(--soc-medium)]" />
            API Key Generated
          </DialogTitle>
          <DialogDescription className="text-xs">
            Store this key securely — it will only be shown once.
          </DialogDescription>
        </DialogHeader>
        <div className="p-5 space-y-3">
          <div className="rounded-md border border-[color:var(--soc-medium)]/40 bg-[color:var(--soc-medium)]/10 p-3">
            <p className="text-[11px] font-bold text-[color:var(--soc-medium)] uppercase tracking-wider">
              ⚠ This key will not be shown again
            </p>
            <p className="mt-1 text-[10px] text-muted-foreground">
              Copy it now and store it in your agent configuration. If you lose it, you will need to rotate the key.
            </p>
          </div>
          <div className="rounded-md border border-border/40 bg-background/30 p-3">
            <div className="flex items-center gap-2">
              <code className="flex-1 break-all font-mono-data text-xs text-foreground">
                {apiKey}
              </code>
              <Button
                size="sm"
                variant="outline"
                className="shrink-0 gap-1.5 text-[11px]"
                onClick={handleCopy}
              >
                {copied ? <Check className="h-3 w-3 text-[color:var(--soc-success)]" /> : <Copy className="h-3 w-3" />}
                {copied ? "Copied" : "Copy"}
              </Button>
            </div>
          </div>
        </div>
        <DialogFooter className="border-t border-border/60 bg-card/30 px-5 py-3">
          <Button size="sm" onClick={onClose}>I&apos;ve saved the key</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
