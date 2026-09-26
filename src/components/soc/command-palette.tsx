"use client";

import { useEffect, useState, useCallback } from "react";
import {
  CommandDialog,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
  CommandSeparator,
  CommandShortcut,
} from "@/components/ui/command";
import {
  Activity,
  Swords,
  Shield,
  ScrollText,
  FileText,
  Settings as SettingsIcon,
  Radar,
  Play,
  Square,
  Search,
  BookOpen,
  Download,
  Zap,
} from "lucide-react";
import { useAppStore } from "@/lib/store";
import { api } from "@/lib/api-client";
import { toast } from "sonner";
import type { ViewKey } from "@/lib/types";

interface CommandPaletteProps {
  onOpenRules: () => void;
}

export function CommandPalette({ onOpenRules }: CommandPaletteProps) {
  const [open, setOpen] = useState(false);
  const view = useAppStore((s) => s.view);
  const setView = useAppStore((s) => s.setView);
  const sessionId = useAppStore((s) => s.sessionId);
  const status = useAppStore((s) => s.status);
  const targetAddress = useAppStore((s) => s.targetAddress);

  // Listen for Cmd+K / Ctrl+K
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setOpen((v) => !v);
      }
    };
    document.addEventListener("keydown", handler);
    return () => document.removeEventListener("keydown", handler);
  }, []);

  const navigate = useCallback(
    (v: ViewKey) => {
      setView(v);
      setOpen(false);
    },
    [setView],
  );

  const handleStartMonitoring = useCallback(async () => {
    setOpen(false);
    if (sessionId) return;
    try {
      const res = await api.startMonitoring(targetAddress || "192.168.1.100", "demo");
      useAppStore.getState().startSession({
        sessionId: res.sessionId,
        targetAddress: res.session.targetAddress || targetAddress || "192.168.1.100",
        mode: res.session.mode || "demo",
        assessment: res.assessment,
      });
      toast.success("Monitoring started via command palette");
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to start monitoring");
    }
  }, [sessionId, targetAddress]);

  const handleStopMonitoring = useCallback(async () => {
    setOpen(false);
    if (!sessionId) return;
    try {
      await api.stopMonitoring(sessionId);
      useAppStore.getState().stopSession();
      toast.success("Monitoring stopped via command palette");
      setTimeout(() => useAppStore.getState().resetSession(), 1000);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to stop monitoring");
    }
  }, [sessionId]);

  const handleGenerateReport = useCallback(async () => {
    setOpen(false);
    if (!sessionId) {
      toast.info("Start a monitoring session first");
      return;
    }
    try {
      toast.info("Generating report…");
      await api.generateReport(sessionId);
      toast.success("Report generated. Switching to Reports view.");
      setView("reports");
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to generate report");
    }
  }, [sessionId, setView]);

  const isActive = status === "monitoring" || status === "scanning" || status === "initializing";

  return (
    <CommandDialog
      open={open}
      onOpenChange={setOpen}
      title="LiveSOC Command Palette"
      description="Quick navigation and actions"
      className="max-w-xl"
    >
      <CommandInput placeholder="Type a command or search…" />
      <CommandList className="max-h-[400px]">
        <CommandEmpty>No results found.</CommandEmpty>

        <CommandGroup heading="Navigation">
          <CommandItem onSelect={() => navigate("monitor")}>
            <Activity className="h-4 w-4" />
            <span>Live Monitor</span>
            {view === "monitor" && <CommandShortcut>current</CommandShortcut>}
          </CommandItem>
          <CommandItem onSelect={() => navigate("offense")}>
            <Swords className="h-4 w-4 text-[color:var(--soc-critical)]" />
            <span>Offense Analysis</span>
            {view === "offense" && <CommandShortcut>current</CommandShortcut>}
          </CommandItem>
          <CommandItem onSelect={() => navigate("defense")}>
            <Shield className="h-4 w-4 text-[color:var(--soc-low)]" />
            <span>Defense Guidance</span>
            {view === "defense" && <CommandShortcut>current</CommandShortcut>}
          </CommandItem>
          <CommandItem onSelect={() => navigate("history")}>
            <ScrollText className="h-4 w-4" />
            <span>History</span>
            {view === "history" && <CommandShortcut>current</CommandShortcut>}
          </CommandItem>
          <CommandItem onSelect={() => navigate("reports")}>
            <FileText className="h-4 w-4" />
            <span>Reports</span>
            {view === "reports" && <CommandShortcut>current</CommandShortcut>}
          </CommandItem>
          <CommandItem onSelect={() => navigate("settings")}>
            <SettingsIcon className="h-4 w-4" />
            <span>Settings</span>
            {view === "settings" && <CommandShortcut>current</CommandShortcut>}
          </CommandItem>
        </CommandGroup>

        <CommandSeparator />

        <CommandGroup heading="Actions">
          {!isActive ? (
            <CommandItem onSelect={handleStartMonitoring}>
              <Play className="h-4 w-4 text-[color:var(--soc-success)]" />
              <span>Start Monitoring ({targetAddress || "192.168.1.100"})</span>
              <CommandShortcut>demo</CommandShortcut>
            </CommandItem>
          ) : (
            <CommandItem onSelect={handleStopMonitoring}>
              <Square className="h-4 w-4 text-[color:var(--soc-critical)]" />
              <span>Stop Monitoring</span>
              <CommandShortcut>active</CommandShortcut>
            </CommandItem>
          )}
          <CommandItem onSelect={handleGenerateReport} disabled={!sessionId}>
            <Download className="h-4 w-4" />
            <span>Generate Report from Active Session</span>
            {!sessionId && <CommandShortcut>no session</CommandShortcut>}
          </CommandItem>
        </CommandGroup>

        <CommandSeparator />

        <CommandGroup heading="Reference">
          <CommandItem onSelect={() => { onOpenRules(); setOpen(false); }}>
            <BookOpen className="h-4 w-4" />
            <span>Detection Rules Reference</span>
            <CommandShortcut>8 rules</CommandShortcut>
          </CommandItem>
          <CommandItem onSelect={() => { navigate("settings"); }}>
            <Radar className="h-4 w-4" />
            <span>Configure Telemetry Collectors</span>
          </CommandItem>
        </CommandGroup>

        <CommandSeparator />

        <CommandGroup heading="Tips">
          <CommandItem disabled>
            <Zap className="h-4 w-4 text-[color:var(--soc-medium)]" />
            <span>Press Cmd/Ctrl+K anytime to open this palette</span>
          </CommandItem>
          <CommandItem disabled>
            <Search className="h-4 w-4 text-muted-foreground" />
            <span>Start typing to filter commands</span>
          </CommandItem>
        </CommandGroup>
      </CommandList>
    </CommandDialog>
  );
}
