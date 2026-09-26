"use client";

import { useState } from "react";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Button } from "@/components/ui/button";
import { Download, FileJson, FileSpreadsheet, Loader2 } from "lucide-react";
import { toast } from "sonner";
import {
  exportEventsCsv,
  exportEventsJson,
  exportAlertsCsv,
  exportAlertsJson,
} from "@/lib/export-utils";
import type { SecurityEvent, SecurityAlert } from "@/lib/types";

interface ExportMenuProps {
  events?: SecurityEvent[];
  alerts?: SecurityAlert[];
  targetLabel: string;
  variant?: "default" | "outline" | "ghost" | "secondary";
  size?: "default" | "sm" | "lg" | "icon";
  label?: string;
  disabled?: boolean;
}

export function ExportMenu({
  events,
  alerts,
  targetLabel,
  variant = "outline",
  size = "sm",
  label = "Export",
  disabled = false,
}: ExportMenuProps) {
  const [exporting, setExporting] = useState(false);
  const hasEvents = events && events.length > 0;
  const hasAlerts = alerts && alerts.length > 0;

  const safeLabel = targetLabel.replace(/[^a-zA-Z0-9.-]/g, "_") || "target";

  const handle = (fn: () => void, what: string) => {
    setExporting(true);
    try {
      fn();
      toast.success(`${what} exported successfully`);
    } catch {
      toast.error(`Failed to export ${what}`);
    } finally {
      setTimeout(() => setExporting(false), 300);
    }
  };

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button
          variant={variant}
          size={size}
          disabled={disabled || exporting || (!hasEvents && !hasAlerts)}
          className="font-mono-data text-[10px] uppercase tracking-wider gap-1.5"
        >
          {exporting ? (
            <Loader2 className="h-3 w-3 animate-spin" />
          ) : (
            <Download className="h-3 w-3" />
          )}
          <span className="hidden sm:inline">{label}</span>
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-48">
        {hasEvents && (
          <>
            <DropdownMenuLabel className="font-mono-data text-[10px] uppercase tracking-wider text-muted-foreground">
              Events ({events!.length})
            </DropdownMenuLabel>
            <DropdownMenuItem
              onClick={() => handle(() => exportEventsCsv(events!, safeLabel), "Events CSV")}
              className="gap-2 text-xs"
            >
              <FileSpreadsheet className="h-3.5 w-3.5 text-[color:var(--soc-success)]" />
              Events as CSV
            </DropdownMenuItem>
            <DropdownMenuItem
              onClick={() => handle(() => exportEventsJson(events!, safeLabel), "Events JSON")}
              className="gap-2 text-xs"
            >
              <FileJson className="h-3.5 w-3.5 text-[color:var(--soc-low)]" />
              Events as JSON
            </DropdownMenuItem>
          </>
        )}
        {hasEvents && hasAlerts && <DropdownMenuSeparator />}
        {hasAlerts && (
          <>
            <DropdownMenuLabel className="font-mono-data text-[10px] uppercase tracking-wider text-muted-foreground">
              Alerts ({alerts!.length})
            </DropdownMenuLabel>
            <DropdownMenuItem
              onClick={() => handle(() => exportAlertsCsv(alerts!, safeLabel), "Alerts CSV")}
              className="gap-2 text-xs"
            >
              <FileSpreadsheet className="h-3.5 w-3.5 text-[color:var(--soc-success)]" />
              Alerts as CSV
            </DropdownMenuItem>
            <DropdownMenuItem
              onClick={() => handle(() => exportAlertsJson(alerts!, safeLabel), "Alerts JSON")}
              className="gap-2 text-xs"
            >
              <FileJson className="h-3.5 w-3.5 text-[color:var(--soc-low)]" />
              Alerts as JSON
            </DropdownMenuItem>
          </>
        )}
        {!hasEvents && !hasAlerts && (
          <div className="px-2 py-3 text-center text-xs text-muted-foreground">
            No data to export
          </div>
        )}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
