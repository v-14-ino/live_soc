"use client";

import { useMemo, useState, useRef, useCallback, useEffect } from "react";
import type { SecurityEvent } from "@/lib/types";
import { severityColor } from "@/lib/constants";
import { Play, Pause, SkipBack, SkipForward, Clock, Repeat, Gauge } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";

interface TimelineScrubberProps {
  events: SecurityEvent[];
  onScrub?: (events: SecurityEvent[]) => void;
  className?: string;
}

// ============================================================
// Timeline Scrubber — visual event density timeline with playback
//
// Shows a histogram of events over the session duration.
// Drag the playhead to "scrub" through events. Play button
// auto-advances. onScrub is called with events up to the playhead.
// ============================================================

const BUCKET_COUNT = 60; // 60 buckets across the timeline
const BASE_INTERVAL_MS = 200; // base interval per bucket at 1x speed

type PlaybackSpeed = 0.5 | 1 | 2 | 4;
const SPEEDS: PlaybackSpeed[] = [0.5, 1, 2, 4];
const SPEED_LABEL: Record<PlaybackSpeed, string> = {
  0.5: "0.5×",
  1: "1×",
  2: "2×",
  4: "4×",
};

export function TimelineScrubber({ events, onScrub, className }: TimelineScrubberProps) {
  const sortedEvents = useMemo(
    () => [...events].sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()),
    [events],
  );

  const { startMs, endMs, durationMs, buckets, maxBucket } = useMemo(() => {
    if (sortedEvents.length === 0) {
      return { startMs: 0, endMs: 0, durationMs: 0, buckets: [] as number[], maxBucket: 0 };
    }
    const startMs = new Date(sortedEvents[0].timestamp).getTime();
    const endMs = new Date(sortedEvents[sortedEvents.length - 1].timestamp).getTime();
    const durationMs = Math.max(1000, endMs - startMs); // min 1s
    const buckets: number[] = new Array(BUCKET_COUNT).fill(0);
    const severityBuckets: SecurityEvent[][][] = new Array(BUCKET_COUNT).fill(null).map(() => []);
    for (const e of sortedEvents) {
      const t = new Date(e.timestamp).getTime();
      const idx = Math.min(BUCKET_COUNT - 1, Math.max(0, Math.floor(((t - startMs) / durationMs) * BUCKET_COUNT)));
      buckets[idx]++;
      severityBuckets[idx].push(e);
    }
    const maxBucket = Math.max(1, ...buckets);
    return { startMs, endMs, durationMs, buckets, maxBucket };
  }, [sortedEvents]);

  const [playhead, setPlayhead] = useState(1); // 0..1 (fraction of timeline)
  const [playing, setPlaying] = useState(false);
  const [loop, setLoop] = useState(false);
  const [speed, setSpeed] = useState<PlaybackSpeed>(1);
  const barRef = useRef<HTMLDivElement>(null);
  const draggingRef = useRef(false);

  const intervalMs = Math.round(BASE_INTERVAL_MS / speed);

  // Events up to the playhead
  const visibleEvents = useMemo(() => {
    if (sortedEvents.length === 0) return [];
    const cutoff = startMs + playhead * durationMs;
    return sortedEvents.filter((e) => new Date(e.timestamp).getTime() <= cutoff);
  }, [sortedEvents, playhead, startMs, durationMs]);

  // Notify parent of scrub
  useEffect(() => {
    onScrub?.(visibleEvents);
  }, [visibleEvents, onScrub]);

  // Playback
  useEffect(() => {
    if (!playing || sortedEvents.length === 0) return;
    const step = 1 / BUCKET_COUNT;
    const id = setInterval(() => {
      setPlayhead((prev) => {
        const next = prev + step;
        if (next >= 1) {
          if (loop) {
            return 0;
          }
          setPlaying(false);
          return 1;
        }
        return next;
      });
    }, intervalMs);
    return () => clearInterval(id);
  }, [playing, sortedEvents.length, loop, intervalMs]);

  // Scrub via pointer
  const handlePointer = useCallback((clientX: number) => {
    if (!barRef.current) return;
    const rect = barRef.current.getBoundingClientRect();
    const frac = Math.max(0, Math.min(1, (clientX - rect.left) / rect.width));
    setPlayhead(frac);
  }, []);

  const handlePointerDown = useCallback((e: React.PointerEvent) => {
    e.preventDefault();
    draggingRef.current = true;
    setPlaying(false);
    handlePointer(e.clientX);
    (e.target as HTMLElement).setPointerCapture?.(e.pointerId);
  }, [handlePointer]);

  const handlePointerMove = useCallback((e: React.PointerEvent) => {
    if (!draggingRef.current) return;
    handlePointer(e.clientX);
  }, [handlePointer]);

  const handlePointerUp = useCallback(() => {
    draggingRef.current = false;
  }, []);

  const handleSkipStart = useCallback(() => {
    setPlaying(false);
    setPlayhead(0);
  }, []);

  const handleSkipEnd = useCallback(() => {
    setPlaying(false);
    setPlayhead(1);
  }, []);

  const handlePlayToggle = useCallback(() => {
    if (playhead >= 1) setPlayhead(0);
    setPlaying((p) => !p);
  }, [playhead]);

  // Format time from playhead position
  const playheadTime = useMemo(() => {
    if (durationMs === 0) return "—";
    const t = new Date(startMs + playhead * durationMs);
    return t.toLocaleTimeString("en-US", { hour12: false });
  }, [playhead, startMs, durationMs]);

  const elapsedSec = Math.round(playhead * (durationMs / 1000));
  const totalSec = Math.round(durationMs / 1000);

  if (sortedEvents.length === 0) {
    return null;
  }

  return (
    <div className={`rounded-lg border border-border/60 bg-card/40 p-3 ${className ?? ""}`}>
      <div className="mb-2 flex items-center justify-between">
        <div className="flex items-center gap-1.5 font-mono-data text-[9px] uppercase tracking-wider text-muted-foreground">
          <Clock className="h-3 w-3" />
          Timeline Scrubber
        </div>
        <div className="flex items-center gap-2 font-mono-data text-[10px] text-muted-foreground">
          <span className="text-[color:var(--soc-low)]">{playheadTime}</span>
          <span className="text-muted-foreground/40">/</span>
          <span>{new Date(endMs).toLocaleTimeString("en-US", { hour12: false })}</span>
          <span className="text-muted-foreground/40">·</span>
          <span>{elapsedSec}s / {totalSec}s</span>
          <span className="text-muted-foreground/40">·</span>
          <span className="text-foreground">{visibleEvents.length} / {sortedEvents.length} events</span>
        </div>
      </div>

      {/* Controls */}
      <div className="mb-2 flex items-center gap-1.5">
        <Button
          size="sm"
          variant="outline"
          className="h-7 w-7 p-0"
          onClick={handleSkipStart}
          title="Jump to start"
        >
          <SkipBack className="h-3 w-3" />
        </Button>
        <Button
          size="sm"
          variant={playing ? "secondary" : "default"}
          className="h-7 gap-1.5 px-2.5 text-[11px]"
          onClick={handlePlayToggle}
          title={playing ? "Pause" : "Play"}
        >
          {playing ? <Pause className="h-3 w-3" /> : <Play className="h-3 w-3" />}
          {playing ? "Pause" : "Play"}
        </Button>
        <Button
          size="sm"
          variant="outline"
          className="h-7 w-7 p-0"
          onClick={handleSkipEnd}
          title="Jump to end"
        >
          <SkipForward className="h-3 w-3" />
        </Button>
        <Button
          size="sm"
          variant={loop ? "secondary" : "outline"}
          className={`h-7 w-7 p-0 ${loop ? "text-[color:var(--soc-low)]" : ""}`}
          onClick={() => setLoop((v) => !v)}
          title="Loop playback"
        >
          <Repeat className="h-3 w-3" />
        </Button>
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button
              size="sm"
              variant="outline"
              className="h-7 gap-1.5 px-2 text-[11px] font-mono-data"
              title="Playback speed"
            >
              <Gauge className="h-3 w-3" />
              {SPEED_LABEL[speed]}
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="start" className="w-28">
            <DropdownMenuLabel className="font-mono-data text-[9px] uppercase tracking-wider text-muted-foreground">
              Speed
            </DropdownMenuLabel>
            <DropdownMenuSeparator />
            {SPEEDS.map((s) => (
              <DropdownMenuItem
                key={s}
                onClick={() => setSpeed(s)}
                className={`gap-2 text-xs ${s === speed ? "text-[color:var(--soc-low)]" : ""}`}
              >
                <span className="font-mono-data">{SPEED_LABEL[s]}</span>
                {s === speed && <span className="ml-auto text-[10px]">✓</span>}
              </DropdownMenuItem>
            ))}
          </DropdownMenuContent>
        </DropdownMenu>
      </div>

      {/* Timeline bar */}
      <div
        ref={barRef}
        className="relative h-16 cursor-pointer touch-none select-none rounded-md border border-border/40 bg-background/40"
        onPointerDown={handlePointerDown}
        onPointerMove={handlePointerMove}
        onPointerUp={handlePointerUp}
        onPointerCancel={handlePointerUp}
      >
        {/* Histogram bars */}
        <div className="absolute inset-0 flex items-end gap-px p-1">
          {buckets.map((count, i) => {
            const frac = count / maxBucket;
            const frac4 = Math.max(0.04, frac);
            return (
              <div
                key={i}
                className="flex-1 rounded-t-sm transition-all"
                style={{
                  height: `${frac4 * 100}%`,
                  backgroundColor: i / BUCKET_COUNT <= playhead
                    ? "color-mix(in oklch, var(--soc-low) 60%, transparent)"
                    : "color-mix(in oklch, var(--muted-foreground) 25%, transparent)",
                  minHeight: count > 0 ? "2px" : "0",
                }}
                title={`${count} events in this bucket`}
              />
            );
          })}
        </div>

        {/* Playhead */}
        <div
          className="pointer-events-none absolute top-0 bottom-0 w-0.5 bg-[color:var(--soc-low)] shadow-[0_0_6px_var(--soc-low)]"
          style={{ left: `${playhead * 100}%` }}
        >
          <div className="absolute -top-1 left-1/2 h-2 w-2 -translate-x-1/2 rotate-45 rounded-sm bg-[color:var(--soc-low)]" />
        </div>

        {/* Start/end labels */}
        <div className="pointer-events-none absolute bottom-0.5 left-1.5 font-mono-data text-[8px] text-muted-foreground/60">
          {new Date(startMs).toLocaleTimeString("en-US", { hour12: false })}
        </div>
        <div className="pointer-events-none absolute bottom-0.5 right-1.5 font-mono-data text-[8px] text-muted-foreground/60">
          {new Date(endMs).toLocaleTimeString("en-US", { hour12: false })}
        </div>
      </div>
    </div>
  );
}
