"use client";

import { useState, useEffect, useCallback } from "react";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { SeverityBadge } from "@/components/soc/severity-badge";
import { api } from "@/lib/api-client";
import { describeCondition } from "@/lib/monitoring/custom-rules";
import type { CustomRule, CustomRuleInput, RuleCondition, RuleField, RuleOperator, Severity } from "@/lib/types";
import {
  Plus,
  Trash2,
  Pencil,
  X,
  GripVertical,
  Save,
  AlertCircle,
  Zap,
  FlaskConical,
  LayoutGrid,
  KeyRound,
  ScanLine,
  Globe,
  Eye,
  ShieldAlert,
  AlertOctagon,
  Radar,
  Database,
  Check,
} from "lucide-react";
import { toast } from "sonner";
import { RULE_TEMPLATES, type RuleTemplate } from "@/lib/rule-templates";

// ============================================================
// Custom Rules Manager
//
// Full CRUD UI for user-defined detection rules.
// Each rule has: name, severity, conditions (AND), threshold,
// window, confidence, recommended action, enabled toggle.
// ============================================================

const FIELDS: { value: RuleField; label: string }[] = [
  { value: "sourceIp", label: "Source IP" },
  { value: "destPort", label: "Dest Port" },
  { value: "protocol", label: "Protocol" },
  { value: "eventType", label: "Event Type" },
  { value: "severity", label: "Severity" },
  { value: "message", label: "Message" },
  { value: "sourceCollector", label: "Source Collector" },
];

const OPERATORS: { value: RuleOperator; label: string }[] = [
  { value: "equals", label: "equals" },
  { value: "contains", label: "contains" },
  { value: "matches", label: "matches (regex)" },
  { value: "greaterThan", label: "greater than" },
  { value: "lessThan", label: "less than" },
  { value: "in", label: "in (comma list)" },
];

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

interface CustomRulesManagerProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export function CustomRulesManager({ open, onOpenChange }: CustomRulesManagerProps) {
  const [rules, setRules] = useState<CustomRule[]>([]);
  const [loading, setLoading] = useState(false);
  const [editingRule, setEditingRule] = useState<CustomRule | null>(null);
  const [showEditor, setShowEditor] = useState(false);
  const [showTemplates, setShowTemplates] = useState(false);
  const [creatingFromTemplate, setCreatingFromTemplate] = useState(false);

  const fetchRules = useCallback(async () => {
    setLoading(true);
    try {
      const res = await api.getCustomRules();
      setRules(res.rules);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to load custom rules");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (open) fetchRules();
  }, [open, fetchRules]);

  const handleDelete = useCallback(async (ruleId: string, name: string) => {
    if (!window.confirm(`Delete custom rule "${name}"? This cannot be undone.`)) return;
    try {
      await api.deleteCustomRule(ruleId);
      setRules((prev) => prev.filter((r) => r.ruleId !== ruleId));
      toast.success(`Rule "${name}" deleted`);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to delete rule");
    }
  }, []);

  const handleToggle = useCallback(async (rule: CustomRule) => {
    try {
      await api.updateCustomRule(rule.ruleId, { enabled: !rule.enabled });
      setRules((prev) =>
        prev.map((r) => (r.ruleId === rule.ruleId ? { ...r, enabled: !r.enabled } : r)),
      );
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to toggle rule");
    }
  }, []);

  const handleEdit = useCallback((rule: CustomRule) => {
    setEditingRule(rule);
    setShowEditor(true);
  }, []);

  const handleCreate = useCallback(() => {
    setEditingRule(null);
    setShowEditor(true);
  }, []);

  const handleUseTemplate = useCallback(async (template: RuleTemplate) => {
    setCreatingFromTemplate(true);
    try {
      const input: CustomRuleInput = {
        name: template.name,
        description: template.description,
        severity: template.severity,
        enabled: true,
        conditions: template.conditions.map((c) => ({ ...c })),
        threshold: template.threshold,
        windowMs: template.windowMs,
        confidence: template.confidence,
        recommendedAction: template.recommendedAction,
      };
      const res = await api.createCustomRule(input);
      setRules((prev) => [res.rule, ...prev]);
      setShowTemplates(false);
      toast.success(`Template "${template.name}" created as ${res.rule.ruleId}`);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to create rule from template");
    } finally {
      setCreatingFromTemplate(false);
    }
  }, []);

  const handleSaved = useCallback((rule: CustomRule) => {
    setRules((prev) => {
      const idx = prev.findIndex((r) => r.ruleId === rule.ruleId);
      if (idx >= 0) {
        const next = [...prev];
        next[idx] = rule;
        return next;
      }
      return [rule, ...prev];
    });
    setShowEditor(false);
    setEditingRule(null);
  }, []);

  const enabledCount = rules.filter((r) => r.enabled).length;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[90vh] max-w-4xl overflow-hidden p-0 gap-0">
        <DialogHeader className="border-b border-border/60 px-5 py-4">
          <DialogTitle className="flex items-center gap-2 font-mono-data text-sm uppercase tracking-wider">
            <FlaskConical className="h-4 w-4 text-[color:var(--soc-medium)]" />
            Custom Detection Rules
          </DialogTitle>
          <DialogDescription className="text-xs">
            User-defined rules evaluated alongside the {`8`} built-in rules. {enabledCount} of {rules.length} enabled.
          </DialogDescription>
        </DialogHeader>

        <div className="soc-scrollbar max-h-[calc(90vh-140px)] overflow-y-auto p-5">
          {loading ? (
            <div className="space-y-2">
              {[1, 2, 3].map((i) => (
                <div key={i} className="h-24 animate-pulse rounded-md bg-muted/30" />
              ))}
            </div>
          ) : rules.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-12">
              <FlaskConical className="h-10 w-10 text-muted-foreground/30" />
              <p className="mt-3 font-mono-data text-xs uppercase tracking-wider text-muted-foreground/60">
                No custom rules yet
              </p>
              <p className="mt-1 text-xs text-muted-foreground">
                Create a rule to detect specific activity patterns in your authorized scope.
              </p>
              <Button onClick={handleCreate} className="mt-4 gap-1.5" size="sm">
                <Plus className="h-3.5 w-3.5" />
                Create First Rule
              </Button>
            </div>
          ) : (
            <div className="space-y-2">
              {rules.map((rule) => (
                <div
                  key={rule.ruleId}
                  className={`rounded-md border bg-card/30 p-3 transition-opacity ${
                    rule.enabled ? "border-border/60 opacity-100" : "border-border/40 opacity-60"
                  }`}
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2">
                        <span className="font-mono-data text-[10px] font-bold text-[color:var(--soc-low)]">
                          {rule.ruleId}
                        </span>
                        <SeverityBadge severity={rule.severity} size="sm" />
                        <span className="text-sm font-semibold text-foreground">{rule.name}</span>
                        {rule.firedCount > 0 && (
                          <span className="rounded-sm border border-[color:var(--soc-high)]/40 bg-[color:var(--soc-high)]/10 px-1.5 py-0.5 font-mono-data text-[9px] font-bold uppercase text-[color:var(--soc-high)]">
                            Fired {rule.firedCount}×
                          </span>
                        )}
                      </div>
                      {rule.description && (
                        <p className="mt-1 text-[11px] text-muted-foreground">{rule.description}</p>
                      )}
                      <div className="mt-2 flex flex-wrap items-center gap-1.5">
                        {rule.conditions.map((c, i) => (
                          <span
                            key={i}
                            className="rounded-sm border border-border/40 bg-background/40 px-1.5 py-0.5 font-mono-data text-[9px] text-foreground/70"
                          >
                            {describeCondition(c)}
                          </span>
                        ))}
                      </div>
                      <div className="mt-1.5 flex items-center gap-3 font-mono-data text-[9px] text-muted-foreground">
                        <span>threshold: {rule.threshold}</span>
                        <span>·</span>
                        <span>window: {rule.windowMs / 1000}s</span>
                        <span>·</span>
                        <span>confidence: {rule.confidence}%</span>
                      </div>
                    </div>
                    <div className="flex shrink-0 items-center gap-1">
                      <Switch
                        checked={rule.enabled}
                        onCheckedChange={() => handleToggle(rule)}
                        aria-label="Toggle rule"
                      />
                      <Button
                        size="sm"
                        variant="ghost"
                        className="h-7 w-7 p-0"
                        onClick={() => handleEdit(rule)}
                        title="Edit rule"
                      >
                        <Pencil className="h-3 w-3" />
                      </Button>
                      <Button
                        size="sm"
                        variant="ghost"
                        className="h-7 w-7 p-0 text-[color:var(--soc-critical)] hover:text-[color:var(--soc-critical)]"
                        onClick={() => handleDelete(rule.ruleId, rule.name)}
                        title="Delete rule"
                      >
                        <Trash2 className="h-3 w-3" />
                      </Button>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="flex items-center justify-between border-t border-border/60 bg-card/30 px-5 py-3">
          <span className="font-mono-data text-[10px] text-muted-foreground">
            {enabledCount} enabled · {rules.length} total
          </span>
          <div className="flex items-center gap-2">
            <Button
              onClick={() => setShowTemplates(true)}
              variant="outline"
              size="sm"
              className="gap-1.5"
            >
              <LayoutGrid className="h-3.5 w-3.5" />
              Templates
            </Button>
            <Button onClick={handleCreate} size="sm" className="gap-1.5">
              <Plus className="h-3.5 w-3.5" />
              New Rule
            </Button>
          </div>
        </div>
      </DialogContent>

      {showTemplates && (
        <TemplateGallery
          onClose={() => setShowTemplates(false)}
          onUseTemplate={handleUseTemplate}
          creating={creatingFromTemplate}
        />
      )}

      {showEditor && (
        <RuleEditor
          rule={editingRule}
          onClose={() => {
            setShowEditor(false);
            setEditingRule(null);
          }}
          onSaved={handleSaved}
        />
      )}
    </Dialog>
  );
}

// ============================================================
// Rule Editor (create/edit a single rule)
// ============================================================

interface RuleEditorProps {
  rule: CustomRule | null;
  onClose: () => void;
  onSaved: (rule: CustomRule) => void;
}

function RuleEditor({ rule, onClose, onSaved }: RuleEditorProps) {
  const [name, setName] = useState(rule?.name ?? "");
  const [description, setDescription] = useState(rule?.description ?? "");
  const [severity, setSeverity] = useState<Severity>(rule?.severity ?? "medium");
  const [enabled, setEnabled] = useState(rule?.enabled ?? true);
  const [conditions, setConditions] = useState<RuleCondition[]>(
    rule?.conditions ?? [{ field: "sourceIp", operator: "equals", value: "" }],
  );
  const [threshold, setThreshold] = useState(rule?.threshold ?? 1);
  const [windowMs, setWindowMs] = useState(rule?.windowMs ?? 60000);
  const [confidence, setConfidence] = useState(rule?.confidence ?? 60);
  const [recommendedAction, setRecommendedAction] = useState(rule?.recommendedAction ?? "");
  const [saving, setSaving] = useState(false);
  const [errors, setErrors] = useState<string[]>([]);

  const handleAddCondition = () => {
    setConditions([...conditions, { field: "sourceIp", operator: "equals", value: "" }]);
  };

  const handleRemoveCondition = (index: number) => {
    setConditions(conditions.filter((_, i) => i !== index));
  };

  const handleConditionChange = (index: number, patch: Partial<RuleCondition>) => {
    setConditions(conditions.map((c, i) => (i === index ? { ...c, ...patch } : c)));
  };

  const handleSave = async () => {
    setErrors([]);
    const newErrors: string[] = [];
    if (!name.trim()) newErrors.push("Rule name is required");
    if (conditions.length === 0) newErrors.push("At least one condition is required");
    for (let i = 0; i < conditions.length; i++) {
      const c = conditions[i];
      if (!c.value || c.value === "" || (Array.isArray(c.value) && c.value.length === 0)) {
        newErrors.push(`Condition ${i + 1}: value is required`);
      }
    }
    if (newErrors.length > 0) {
      setErrors(newErrors);
      return;
    }

    setSaving(true);
    try {
      const input: CustomRuleInput = {
        name: name.trim(),
        description,
        severity,
        enabled,
        conditions,
        threshold,
        windowMs,
        confidence,
        recommendedAction,
      };
      let saved: CustomRule;
      if (rule) {
        const res = await api.updateCustomRule(rule.ruleId, input);
        saved = res.rule;
        toast.success(`Rule "${saved.name}" updated`);
      } else {
        const res = await api.createCustomRule(input);
        saved = res.rule;
        toast.success(`Rule "${saved.name}" created`);
      }
      onSaved(saved);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to save rule");
    } finally {
      setSaving(false);
    }
  };

  return (
    <Dialog open={true} onOpenChange={() => onClose()}>
      <DialogContent className="max-h-[92vh] max-w-2xl overflow-hidden p-0 gap-0">
        <DialogHeader className="border-b border-border/60 px-5 py-4">
          <DialogTitle className="flex items-center gap-2 font-mono-data text-sm uppercase tracking-wider">
            <Zap className="h-4 w-4 text-[color:var(--soc-medium)]" />
            {rule ? `Edit Rule ${rule.ruleId}` : "New Custom Rule"}
          </DialogTitle>
          <DialogDescription className="text-xs">
            Define conditions (AND logic), threshold, and response guidance. The rule fires when {">="}{" "}
            threshold matching events occur within the window.
          </DialogDescription>
        </DialogHeader>

        <div className="soc-scrollbar max-h-[calc(92vh-160px)] overflow-y-auto p-5">
          <div className="space-y-4">
            {/* Name + Severity */}
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <Label className="font-mono-data text-[10px] uppercase tracking-wider">Rule Name</Label>
                <Input
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="e.g. SSH brute force from external"
                  className="font-mono-data text-xs"
                />
              </div>
              <div className="space-y-1.5">
                <Label className="font-mono-data text-[10px] uppercase tracking-wider">Severity</Label>
                <Select value={severity} onValueChange={(v) => setSeverity(v as Severity)}>
                  <SelectTrigger className="text-xs">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {SEVERITIES.map((s) => (
                      <SelectItem key={s} value={s} className="text-xs">
                        {s.toUpperCase()}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>

            {/* Description */}
            <div className="space-y-1.5">
              <Label className="font-mono-data text-[10px] uppercase tracking-wider">Description (optional)</Label>
              <Input
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                placeholder="What this rule detects and why it matters"
                className="text-xs"
              />
            </div>

            {/* Conditions */}
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <Label className="font-mono-data text-[10px] uppercase tracking-wider">
                  Conditions (AND logic)
                </Label>
                <Button size="sm" variant="outline" className="h-7 gap-1 text-[11px]" onClick={handleAddCondition}>
                  <Plus className="h-3 w-3" />
                  Add
                </Button>
              </div>
              <div className="space-y-2">
                {conditions.map((cond, i) => (
                  <div
                    key={i}
                    className="flex items-center gap-1.5 rounded-md border border-border/40 bg-background/30 p-2"
                  >
                    <GripVertical className="h-3.5 w-3.5 shrink-0 text-muted-foreground/40" />
                    <span className="font-mono-data text-[9px] text-muted-foreground">{i + 1}.</span>
                    <Select
                      value={cond.field}
                      onValueChange={(v) => handleConditionChange(i, { field: v as RuleField })}
                    >
                      <SelectTrigger className="h-7 w-[120px] text-[11px]">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {FIELDS.map((f) => (
                          <SelectItem key={f.value} value={f.value} className="text-[11px]">
                            {f.label}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                    <Select
                      value={cond.operator}
                      onValueChange={(v) => handleConditionChange(i, { operator: v as RuleOperator })}
                    >
                      <SelectTrigger className="h-7 w-[130px] text-[11px]">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {OPERATORS.map((o) => (
                          <SelectItem key={o.value} value={o.value} className="text-[11px]">
                            {o.label}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                    <Input
                      value={Array.isArray(cond.value) ? cond.value.join(",") : String(cond.value)}
                      onChange={(e) => {
                        const val = cond.operator === "in"
                          ? e.target.value.split(",").map((s) => s.trim()).filter(Boolean)
                          : cond.field === "destPort"
                            ? Number(e.target.value)
                            : e.target.value;
                        handleConditionChange(i, { value: val });
                      }}
                      placeholder={cond.operator === "in" ? "comma,separated,values" : "value"}
                      className="h-7 flex-1 text-[11px] font-mono-data"
                    />
                    <Button
                      size="sm"
                      variant="ghost"
                      className="h-7 w-7 shrink-0 p-0 text-[color:var(--soc-critical)]"
                      onClick={() => handleRemoveCondition(i)}
                      disabled={conditions.length <= 1}
                    >
                      <X className="h-3 w-3" />
                    </Button>
                  </div>
                ))}
              </div>
            </div>

            {/* Threshold + Window + Confidence */}
            <div className="grid grid-cols-3 gap-3">
              <div className="space-y-1.5">
                <Label className="font-mono-data text-[10px] uppercase tracking-wider">Threshold (events)</Label>
                <Input
                  type="number"
                  min={1}
                  max={1000}
                  value={threshold}
                  onChange={(e) => setThreshold(Math.max(1, Number(e.target.value)))}
                  className="font-mono-data text-xs"
                />
              </div>
              <div className="space-y-1.5">
                <Label className="font-mono-data text-[10px] uppercase tracking-wider">Window (sec)</Label>
                <Input
                  type="number"
                  min={1}
                  max={3600}
                  value={windowMs / 1000}
                  onChange={(e) => setWindowMs(Math.max(1, Number(e.target.value)) * 1000)}
                  className="font-mono-data text-xs"
                />
              </div>
              <div className="space-y-1.5">
                <Label className="font-mono-data text-[10px] uppercase tracking-wider">Confidence (%)</Label>
                <Input
                  type="number"
                  min={1}
                  max={100}
                  value={confidence}
                  onChange={(e) => setConfidence(Math.max(1, Math.min(100, Number(e.target.value))))}
                  className="font-mono-data text-xs"
                />
              </div>
            </div>

            {/* Recommended Action */}
            <div className="space-y-1.5">
              <Label className="font-mono-data text-[10px] uppercase tracking-wider">Recommended Action</Label>
              <Textarea
                value={recommendedAction}
                onChange={(e) => setRecommendedAction(e.target.value)}
                placeholder="What should the analyst do when this rule fires?"
                className="text-xs min-h-[60px]"
              />
            </div>

            {/* Enabled toggle */}
            <div className="flex items-center justify-between rounded-md border border-border/40 bg-background/30 p-3">
              <div>
                <span className="text-xs font-medium">Enabled</span>
                <p className="text-[10px] text-muted-foreground">When disabled, this rule is not evaluated.</p>
              </div>
              <Switch checked={enabled} onCheckedChange={setEnabled} />
            </div>

            {/* Errors */}
            {errors.length > 0 && (
              <div className="rounded-md border border-[color:var(--soc-critical)]/40 bg-[color:var(--soc-critical)]/10 p-3">
                <div className="flex items-center gap-1.5 text-[color:var(--soc-critical)]">
                  <AlertCircle className="h-3.5 w-3.5" />
                  <span className="font-mono-data text-[10px] uppercase tracking-wider">Validation Errors</span>
                </div>
                <ul className="mt-1.5 space-y-0.5 text-[11px] text-foreground/80">
                  {errors.map((e, i) => (
                    <li key={i}>• {e}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        </div>

        <DialogFooter className="border-t border-border/60 bg-card/30 px-5 py-3">
          <Button variant="outline" size="sm" onClick={onClose}>
            Cancel
          </Button>
          <Button size="sm" onClick={handleSave} disabled={saving} className="gap-1.5">
            {saving ? (
              <>
                <div className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-current border-t-transparent" />
                Saving…
              </>
            ) : (
              <>
                <Save className="h-3.5 w-3.5" />
                {rule ? "Update Rule" : "Create Rule"}
              </>
            )}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ============================================================
// Template Gallery — pre-built rule templates
// ============================================================

const TEMPLATE_ICONS: Record<string, typeof KeyRound> = {
  KeyRound,
  ScanLine,
  Globe,
  Eye,
  ShieldAlert,
  AlertOctagon,
  Radar,
  Database,
};

interface TemplateGalleryProps {
  onClose: () => void;
  onUseTemplate: (template: RuleTemplate) => void;
  creating: boolean;
}

function TemplateGallery({ onClose, onUseTemplate, creating }: TemplateGalleryProps) {
  return (
    <Dialog open={true} onOpenChange={() => onClose()}>
      <DialogContent className="max-h-[90vh] max-w-4xl overflow-hidden p-0 gap-0">
        <DialogHeader className="border-b border-border/60 px-5 py-4">
          <DialogTitle className="flex items-center gap-2 font-mono-data text-sm uppercase tracking-wider">
            <LayoutGrid className="h-4 w-4 text-[color:var(--soc-low)]" />
            Rule Templates
          </DialogTitle>
          <DialogDescription className="text-xs">
            One-click create a custom rule from a pre-built template. Customize the conditions after creation.
          </DialogDescription>
        </DialogHeader>

        <div className="soc-scrollbar max-h-[calc(90vh-140px)] overflow-y-auto p-5">
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            {RULE_TEMPLATES.map((template) => {
              const Icon = TEMPLATE_ICONS[template.icon] ?? Zap;
              return (
                <div
                  key={template.id}
                  className="group flex flex-col rounded-lg border border-border/60 bg-card/30 p-4 transition-all hover:border-[color:var(--soc-low)]/40 hover:bg-card/50"
                >
                  <div className="flex items-start gap-3">
                    <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-md bg-[color:var(--soc-low)]/10">
                      <Icon className="h-4.5 w-4.5 text-[color:var(--soc-low)]" />
                    </div>
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2">
                        <h3 className="truncate text-sm font-semibold text-foreground">
                          {template.name}
                        </h3>
                        <SeverityBadge severity={template.severity} size="sm" />
                      </div>
                      <span className="font-mono-data text-[9px] uppercase tracking-wider text-muted-foreground">
                        {template.category}
                      </span>
                    </div>
                  </div>

                  <p className="mt-2 flex-1 text-[11px] leading-relaxed text-muted-foreground">
                    {template.description}
                  </p>

                  <div className="mt-2 flex flex-wrap gap-1">
                    {template.conditions.map((c, i) => (
                      <span
                        key={i}
                        className="rounded-sm border border-border/40 bg-background/40 px-1.5 py-0.5 font-mono-data text-[9px] text-foreground/70"
                      >
                        {describeCondition(c)}
                      </span>
                    ))}
                  </div>

                  <div className="mt-2 flex items-center gap-3 font-mono-data text-[9px] text-muted-foreground">
                    <span>threshold: {template.threshold}</span>
                    <span>·</span>
                    <span>window: {template.windowMs / 1000}s</span>
                    <span>·</span>
                    <span>confidence: {template.confidence}%</span>
                  </div>

                  <div className="mt-2 flex flex-wrap gap-1">
                    {template.tags.map((tag) => (
                      <span
                        key={tag}
                        className="rounded-sm bg-muted/40 px-1 py-0.5 font-mono-data text-[8px] text-muted-foreground"
                      >
                        #{tag}
                      </span>
                    ))}
                  </div>

                  <Button
                    size="sm"
                    variant="outline"
                    className="mt-3 gap-1.5 group-hover:border-[color:var(--soc-low)]/40 group-hover:text-[color:var(--soc-low)]"
                    onClick={() => onUseTemplate(template)}
                    disabled={creating}
                  >
                    {creating ? (
                      <>
                        <div className="h-3 w-3 animate-spin rounded-full border-2 border-current border-t-transparent" />
                        Creating…
                      </>
                    ) : (
                      <>
                        <Check className="h-3 w-3" />
                        Use Template
                      </>
                    )}
                  </Button>
                </div>
              );
            })}
          </div>
        </div>

        <div className="flex items-center justify-end border-t border-border/60 bg-card/30 px-5 py-3">
          <Button variant="outline" size="sm" onClick={onClose}>
            Close
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}
