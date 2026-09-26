"use client";

import { cn } from "@/lib/utils";

interface PanelProps {
  title?: string;
  subtitle?: string;
  icon?: React.ReactNode;
  actions?: React.ReactNode;
  className?: string;
  bodyClassName?: string;
  children: React.ReactNode;
  accent?: "default" | "offense" | "defense";
}

const accentBorder = {
  default: "border-border/60",
  offense: "offense-surface",
  defense: "defense-surface",
};

export function Panel({
  title,
  subtitle,
  icon,
  actions,
  className,
  bodyClassName,
  children,
  accent = "default",
}: PanelProps) {
  return (
    <div
      className={cn(
        "flex flex-col overflow-hidden rounded-lg border bg-card/50 backdrop-blur-sm",
        accentBorder[accent],
        className,
      )}
    >
      {(title || actions) && (
        <div className="flex items-center justify-between gap-2 border-b border-border/50 bg-card/30 px-4 py-2.5">
          <div className="flex min-w-0 items-center gap-2">
            {icon && <span className="shrink-0 text-muted-foreground">{icon}</span>}
            <div className="min-w-0">
              {title && (
                <h3 className="font-mono-data text-xs font-semibold uppercase tracking-wider text-foreground truncate">
                  {title}
                </h3>
              )}
              {subtitle && (
                <p className="text-[10px] text-muted-foreground truncate">{subtitle}</p>
              )}
            </div>
          </div>
          {actions && <div className="flex shrink-0 items-center gap-1">{actions}</div>}
        </div>
      )}
      <div className={cn("flex-1 min-h-0", bodyClassName)}>{children}</div>
    </div>
  );
}
