"use client";

import { useEffect, useCallback, useState } from "react";

// ============================================================
// LiveSOC - Global Keyboard Shortcuts
//
// J/K: navigate events in Live Security Log (down/up)
// A: acknowledge the currently-selected alert
// R: resolve the currently-selected alert
// Space: pause/resume the live event stream
// C: clear the live view (visual only)
// 1-6: switch views (Live Monitor, Offense, Defense, History, Reports, Settings)
// Cmd/Ctrl+K: command palette (handled in CommandPalette)
// ?: show keyboard shortcuts help overlay
// Esc: close any open dialog/drawer/overlay
// ============================================================

export interface KeyboardShortcut {
  key: string;
  description: string;
  group: string;
  shift?: boolean;
}

export const KEYBOARD_SHORTCUTS: KeyboardShortcut[] = [
  { key: "J", description: "Next event in live log", group: "Navigation" },
  { key: "K", description: "Previous event in live log", group: "Navigation" },
  { key: "A", description: "Acknowledge selected alert", group: "Alerts" },
  { key: "R", description: "Resolve selected alert", group: "Alerts" },
  { key: "Space", description: "Pause / resume live stream", group: "Live Monitor" },
  { key: "C", description: "Clear live view (visual only)", group: "Live Monitor" },
  { key: "E", description: "Export events (CSV)", group: "Live Monitor" },
  { key: "1", description: "Go to Live Monitor", group: "Views" },
  { key: "2", description: "Go to Offense", group: "Views" },
  { key: "3", description: "Go to Defense", group: "Views" },
  { key: "4", description: "Go to History", group: "Views" },
  { key: "5", description: "Go to Reports", group: "Views" },
  { key: "6", description: "Go to Settings", group: "Views" },
  { key: "⌘/Ctrl+K", description: "Open command palette", group: "Global" },
  { key: "?", description: "Show this help overlay", group: "Global" },
  { key: "Esc", description: "Close dialog / drawer / overlay", group: "Global" },
];

export interface KeyboardShortcutsOptions {
  onViewChange?: (view: "monitor" | "offense" | "defense" | "history" | "reports" | "settings") => void;
  onEventNavigate?: (direction: "next" | "prev") => void;
  onAlertAck?: () => void;
  onAlertResolve?: () => void;
  onPauseToggle?: () => void;
  onClearView?: () => void;
  onExportEvents?: () => void;
  getCurrentView?: () => string;
}

const VIEW_KEYS: Record<string, "monitor" | "offense" | "defense" | "history" | "reports" | "settings"> = {
  "1": "monitor",
  "2": "offense",
  "3": "defense",
  "4": "history",
  "5": "reports",
  "6": "settings",
};

export function useKeyboardShortcuts(options: KeyboardShortcutsOptions) {
  const [showHelp, setShowHelp] = useState(false);

  const handler = useCallback(
    (e: KeyboardEvent) => {
      // Don't interfere with text inputs, textareas, contenteditable
      const target = e.target as HTMLElement | null;
      const tag = target?.tagName?.toLowerCase();
      const isInput =
        tag === "input" ||
        tag === "textarea" ||
        tag === "select" ||
        target?.isContentEditable ||
        target?.getAttribute("role") === "combobox" ||
        target?.getAttribute("role") === "textbox";

      // Cmd/Ctrl+K is always handled (in CommandPalette), skip here
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") return;

      // ? (Shift+/) shows help — works even in inputs
      if (e.key === "?" && e.shiftKey) {
        e.preventDefault();
        setShowHelp((v) => !v);
        return;
      }

      // Escape closes help
      if (e.key === "Escape" && showHelp) {
        setShowHelp(false);
        return;
      }

      // If in an input, only allow Escape (let the browser/drawer handle it)
      if (isInput) return;

      // Number keys 1-6: switch views
      if (VIEW_KEYS[e.key] && !e.metaKey && !e.ctrlKey && !e.altKey) {
        e.preventDefault();
        options.onViewChange?.(VIEW_KEYS[e.key]);
        return;
      }

      // Don't trigger single-key shortcuts with modifiers
      if (e.metaKey || e.ctrlKey || e.altKey) return;

      const key = e.key.toLowerCase();

      // Only trigger letter shortcuts when on the Live Monitor view
      const currentView = options.getCurrentView?.() ?? "monitor";
      const onMonitor = currentView === "monitor";

      if (key === "j") {
        e.preventDefault();
        if (onMonitor) options.onEventNavigate?.("next");
      } else if (key === "k") {
        e.preventDefault();
        if (onMonitor) options.onEventNavigate?.("prev");
      } else if (key === "a") {
        e.preventDefault();
        if (onMonitor) options.onAlertAck?.();
      } else if (key === "r") {
        e.preventDefault();
        if (onMonitor) options.onAlertResolve?.();
      } else if (key === " " || e.code === "Space") {
        e.preventDefault();
        if (onMonitor) options.onPauseToggle?.();
      } else if (key === "c") {
        e.preventDefault();
        if (onMonitor) options.onClearView?.();
      } else if (key === "e") {
        e.preventDefault();
        if (onMonitor) options.onExportEvents?.();
      }
    },
    [options, showHelp],
  );

  useEffect(() => {
    document.addEventListener("keydown", handler);
    return () => document.removeEventListener("keydown", handler);
  }, [handler]);

  return { showHelp, setShowHelp };
}
