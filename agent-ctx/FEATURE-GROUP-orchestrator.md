# Task FEATURE-GROUP — Alert Grouping/Deduplication

**Agent:** orchestrator (main)
**Task:** Add alert grouping by `ruleId` to the `LiveAlerts` panel in `live-monitor-view.tsx`.

## Context loaded
- Read `worklog.md` FEATURE-ACK + REVIEW-2 sections. Ack workflow, store actions (`upsertAlert`, `updateAlertStatus`), `api.updateAlertStatus`, and existing `LiveAlerts` structure understood.
- `SecurityAlert` has `ruleId`, `ruleName`, `severity`, `status` — grouping key = `ruleId` (no sourceIp on the alert itself).
- `severityColor`, `SEVERITY_ORDER` exist in `src/lib/constants.ts`.
- `animate-fade-in-up` keyframe already defined in `globals.css`.
- `font-mono-data` utility class already defined.

## Plan
1. Add lucide imports: `Layers`, `AlignJustify`, `CheckCheck`, `ShieldCheck`, `ChevronUp`.
2. Define `AlertGroup` interface.
3. Extract reusable `AlertCard` component from existing inline JSX (so grouped expanded view can render same cards).
4. Add `BulkActionButtons` component (Ack All / Resolve All with per-button busy state, parallel `Promise.allSettled`).
5. Add `GroupHeaderCard` component (collapsed card with accent bar, ruleId, count, status summary, time range, bulk actions, chevron toggle).
6. Rewrite `LiveAlerts`:
   - `groupByRule` state (default ON).
   - `expandedGroups` Set state.
   - `groups` useMemo computed from `filtered`.
   - Group toggle button in panel actions area.
   - When grouping ON: render GroupHeaderCard + expandable AlertCard list per group.
   - When grouping OFF: render individual AlertCards (current behavior).
   - Single-alert groups render as individual AlertCards (no collapse, no chevron).

## Verification plan
- `bun run lint` clean.
- `dev.log` clean (no compile errors).
- agent-browser E2E: start monitoring → wait for alert burst (SSH auth failures) → verify grouping → expand → Ack All / Resolve All → toggle Group off → status filters with groups.
