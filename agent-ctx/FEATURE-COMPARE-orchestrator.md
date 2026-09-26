# FEATURE-COMPARE — Compare Sessions feature

## Summary
Added a "Compare Sessions" feature to the LiveSOC History view. Users can toggle
a Compare mode, select exactly two historical monitoring sessions via per-row
checkboxes, and open a wide side-by-side diff dialog that shows the security
posture delta between the two sessions.

## Files
- Created: `src/components/soc/compare-sessions-dialog.tsx` (new, ~900 lines)
  - Public export: `CompareSessionsDialog` (controlled via `sessionAId`, `sessionBId`, `open`, `onOpenChange`)
  - Internal `CompareContent` fetches both session details in parallel via `Promise.all([api.getHistoryDetail(A), api.getHistoryDetail(B)])`
  - Diff sections:
    1. Side headers (A cyan / B amber) with id, target, start→end
    2. 4 summary KPI cards: Events / Alerts / Duration / Risk Level (with ↑↓→ delta indicators)
    3. Severity Distribution (2 columns: A on left, B on right; horizontal bars; per-severity delta on B side)
    4. Source IP Comparison (3 columns: New in B / Disappeared / Common with A→B deltas; capped at top 20 each)
    5. Scenario Comparison (offense + defense side-by-side; per-category status: NEW/ESCALATED/DE-ESCALATED/GONE/SAME)
    6. Top Destination Ports (butterfly chart: A bars grow right-to-center, B bars grow left-to-center, port + delta in middle)
    7. Footer disclaimer
  - All diff computations wrapped in `useMemo`
  - Loading skeleton + error state with `toast.error` from sonner
  - Empty states for sections with no data
- Modified: `src/components/views/history-view.tsx`
  - Added `GitCompare`, `X` icons + `Checkbox` (shadcn) + `CompareSessionsDialog` imports
  - `HistoryHeader`: added `compareMode`, `onToggleCompare`, `selectedCount` props; renders a Compare toggle button (outline→default when active) with a `{N}/2` badge
  - `SessionsTable`: added `compareMode`, `selectedIds`, `onToggleSelect` props; when compareMode is on:
    - Prepends a checkbox column (first column)
    - Each row shows an "A"/"B" selection-order badge next to the session id
    - Non-selected checkboxes are disabled once 2 are selected (`atCapacity` guard)
    - Row click in compare mode toggles selection (instead of opening detail); otherwise behavior is unchanged
    - Replaces the Actions cell with a row index `#N` chip
  - `HistoryView` (main): added `compareMode`, `selectedIds`, `compareDialogOpen` state
    - Compare mode info banner above the table
    - Floating action bar (sticky bottom-center) with: Selected summary chips (A/B with id + event/alert counts), Clear, Cancel, "Compare Selected (N)" (disabled until N=2)
    - `<CompareSessionsDialog sessionAId={selectedIds[0]} sessionBId={selectedIds[1]} ... />` at the root
  - Preserved all existing behavior: list, filters, pagination, detail dialog, refresh, summary KPIs

## Diff computation details
- Event/alert count delta: `B - A`. Positive (more) = red ↑ worsening; negative (fewer) = green ↓ improving; zero = muted →.
- Severity distribution: counts events per severity in each session; bar widths scaled to the max single-severity count across both sessions; per-severity delta shown on B column.
- Source IPs: builds `Map<ip, count>` from each session's events. New-in-B = ips in B not in A (red tint). Disappeared = ips in A not in B (strikethrough, muted). Common = ips in both with `delta = countB - countA` (red/green/neutral).
- Scenarios: dedupes by `category` keeping the highest-severity entry per category per session; compares severity rank to label ESCALATED / DE-ESCALATED / SAME / NEW / GONE. Sorted: escalated, new, de-escalated, same, gone.
- Top dest ports: counts `destPort` per session; takes top 5 each; renders a butterfly layout with A on left (right-aligned bars), port + delta in center, B on right (left-aligned bars).
- Risk score: mirrors `risk-gauge-panel.tsx` logic (critical=25, high=15, medium=8, low=3, info=1, capped 100), mapped to bands LOW/MEDIUM/HIGH/CRITICAL.

## Color coding
- Session A accent: cyan (`var(--soc-low)`)
- Session B accent: amber (`var(--soc-medium)`)
- Worsening delta / new / escalated: red (`var(--soc-critical)`)
- Improving delta / de-escalated: green (`var(--soc-success)`)
- Gone / no-change: muted (`var(--muted-foreground)`)

## Verification
- `bun run lint`: 0 errors, 0 warnings
- `dev.log`: clean compiles, no errors; both `/api/history/<id>` requests returned 200 (Promise.all parallel fetch confirmed)
- agent-browser E2E through gateway (:81):
  1. Navigated to History view — sessions table loaded ✓
  2. Clicked "Compare" toggle button — button label changed to "Comparing", checkbox column appeared in table, floating action bar appeared at bottom ✓
  3. Selected first session — button badge updated to "Comparing 1/2", "Compare Selected (1)" disabled, A chip shown in action bar ✓
  4. Selected second session — badge "Comparing 2/2", "Compare Selected (2)" enabled, A+B chips in action bar ✓
  5. Clicked "Compare Selected (2)" — Compare dialog opened, fetched both sessions in parallel (200ms total), rendered:
     - Side headers A (cyan) / B (amber) with ids, targets, dates ✓
     - 4 summary KPI cards: Events 17→89 (+72 red), Alerts 7→16 (+9 red), Duration 16s→41s (↑), Risk Level MEDIUM 36→CRITICAL 100 (↑) ✓
     - Severity Distribution: A=17 events (all info), B=89 events with breakdown ✓
     - Source IP Comparison: 1 new IP in B (192.168.10.20 ×68), 0 disappeared, 4 common ✓
     - Scenario Comparison: 4 offense scenarios (2 NEW, 2 SAME), defense scenarios ✓
     - Top Destination Ports: butterfly chart with ports 22, 80, 443, 445 and deltas ✓
     - Footer disclaimer ✓
  6. Closed dialog via X button — returned to compare mode with selection preserved ✓
  7. Clicked Cancel — exited compare mode, table reverted to original layout, selection cleared ✓
  8. Opened existing detail dialog (View button) — Overview/Events/Alerts/Offense/Defense/Actions tabs still work ✓
- No console errors throughout

## Constraints honored
- Did NOT break existing History view functionality (list, filters, detail dialog, pagination all verified)
- Compare toggle is additive — when OFF, table behaves exactly as before
- Loading states handled (skeleton in dialog while fetching)
- Error states handled (toast.error on fetch failure + inline error message in dialog)
- Uses `toast` from sonner, lucide-react icons (GitCompare, ArrowUp, ArrowDown, ArrowRight, TrendingUp, TrendingDown, Minus, Activity, AlertTriangle, Clock, Gauge, Network, Swords, Shield, Server)
- Responsive: stacks on mobile (`grid-cols-1 lg:grid-cols-2/3`), side-by-side on desktop
- `useMemo` for all diff computations
- `Promise.all` to fetch both sessions in parallel
- Source IPs capped at top 20, scenarios show all
