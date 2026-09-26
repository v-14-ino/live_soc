"use client";

import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";
import { Keyboard } from "lucide-react";
import { KEYBOARD_SHORTCUTS, type KeyboardShortcut } from "@/hooks/use-keyboard-shortcuts";
import { useMemo } from "react";

interface KeyboardShortcutsDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

function KeyCap({ children }: { children: React.ReactNode }) {
  return (
    <kbd className="inline-flex min-w-[28px] items-center justify-center rounded border border-border/60 bg-card/60 px-1.5 py-0.5 font-mono-data text-[10px] font-semibold text-foreground shadow-[0_1px_0_var(--border)]">
      {children}
    </kbd>
  );
}

function renderKeys(shortcut: KeyboardShortcut) {
  const parts = shortcut.key.split("+");
  return (
    <div className="flex items-center gap-1">
      {parts.map((part, i) => (
        <div key={i} className="flex items-center gap-1">
          {i > 0 && <span className="text-[10px] text-muted-foreground">+</span>}
          <KeyCap>{part.trim()}</KeyCap>
        </div>
      ))}
    </div>
  );
}

export function KeyboardShortcutsDialog({ open, onOpenChange }: KeyboardShortcutsDialogProps) {
  const groups = useMemo(() => {
    const map = new Map<string, KeyboardShortcut[]>();
    for (const s of KEYBOARD_SHORTCUTS) {
      const arr = map.get(s.group) ?? [];
      arr.push(s);
      map.set(s.group, arr);
    }
    return Array.from(map.entries());
  }, []);

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-lg p-0 gap-0 overflow-hidden">
        <DialogHeader className="border-b border-border/60 px-5 py-4">
          <DialogTitle className="flex items-center gap-2 font-mono-data text-sm uppercase tracking-wider">
            <Keyboard className="h-4 w-4 text-[color:var(--soc-low)]" />
            Keyboard Shortcuts
          </DialogTitle>
          <DialogDescription className="text-xs">
            Press these keys to navigate and act faster. Letter shortcuts only work when not typing in an input.
          </DialogDescription>
        </DialogHeader>
        <div className="soc-scrollbar max-h-[60vh] overflow-y-auto p-5">
          <div className="space-y-5">
            {groups.map(([group, shortcuts]) => (
              <div key={group}>
                <h3 className="mb-2.5 font-mono-data text-[10px] uppercase tracking-wider text-muted-foreground">
                  {group}
                </h3>
                <div className="space-y-1.5">
                  {shortcuts.map((s) => (
                    <div
                      key={s.key + s.description}
                      className="flex items-center justify-between gap-3 rounded-md px-2 py-1.5 hover:bg-accent/30 transition-colors"
                    >
                      <span className="text-xs text-foreground/80">{s.description}</span>
                      {renderKeys(s)}
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
          <div className="mt-5 rounded-md border border-[color:var(--soc-medium)]/30 bg-[color:var(--soc-medium)]/5 p-3 text-[10px] text-muted-foreground">
            Tip: Press <KeyCap>?</KeyCap> anytime to toggle this overlay. Press <KeyCap>Esc</KeyCap> to close.
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}
