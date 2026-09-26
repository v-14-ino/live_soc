"use client";

import { cn } from "@/lib/utils";
import { AlertTriangle } from "lucide-react";

interface AuthWarningProps {
  className?: string;
  variant?: "banner" | "inline";
}

export function AuthWarning({ className, variant = "inline" }: AuthWarningProps) {
  if (variant === "banner") {
    return (
      <div
        className={cn(
          "flex items-center gap-2 border border-[color:var(--soc-medium)]/40 bg-[color:var(--soc-medium)]/10 px-3 py-1.5 text-xs text-[color:var(--soc-medium)]",
          className,
        )}
      >
        <AlertTriangle className="h-3.5 w-3.5 shrink-0" />
        <span className="font-medium">
          Only monitor systems you are authorized to assess.
        </span>
      </div>
    );
  }
  return (
    <p
      className={cn(
        "flex items-center gap-1.5 text-[10px] text-muted-foreground",
        className,
      )}
    >
      <AlertTriangle className="h-3 w-3 shrink-0 text-[color:var(--soc-medium)]" />
      <span>Only monitor systems you are authorized to assess.</span>
    </p>
  );
}
