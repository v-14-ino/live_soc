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

// Header bottom-border accent color per panel accent
const accentHeaderLine: Record<NonNullable<PanelProps["accent"]>, string> = {
  default: "color-mix(in oklch, var(--muted-foreground) 35%, transparent)",
  offense: "color-mix(in oklch, var(--soc-critical) 55%, transparent)",
  defense: "color-mix(in oklch, var(--soc-low) 55%, transparent)",
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
  const headerLine = accentHeaderLine[accent];
  const iconColor =
    accent === "offense"
      ? "var(--soc-critical)"
      : accent === "defense"
        ? "var(--soc-low)"
        : "var(--muted-foreground)";

  return (
    <div
      className={cn(
        "flex flex-col overflow-hidden rounded-lg border bg-card/50 backdrop-blur-sm",
        accentBorder[accent],
        className,
      )}
    >
      {(title || actions) && (
        <div
          className="group/header relative flex items-center justify-between gap-2 border-b border-border/50 px-4 py-2.5 transition-colors duration-200 hover:bg-card/40"
          style={{
            background:
              "linear-gradient(180deg, color-mix(in oklch, var(--card) 40%, transparent), color-mix(in oklch, var(--card) 20%, transparent))",
          }}
        >
          <div className="flex min-w-0 items-center gap-2">
            {icon && (
              <span className="shrink-0 transition-colors" style={{ color: iconColor }}>
                {icon}
              </span>
            )}
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
          {/* Thin accent line at the bottom of the header */}
          <div
            className="pointer-events-none absolute inset-x-0 bottom-0 h-px"
            style={{ background: headerLine }}
          />
        </div>
      )}
      <div className={cn("glass flex-1 min-h-0", bodyClassName)}>{children}</div>
    </div>
  );
}
