# Task 5-a — LiveMonitor View Implementation

**Agent:** frontend-live-monitor
**Task ID:** 5-a
**Date:** 2026-09-26

## Summary
Replaced the stub at `src/components/views/live-monitor-view.tsx` with the full LiveMonitor operational dashboard — the primary view of the LiveSOC platform.

## Files Modified
- `src/components/views/live-monitor-view.tsx` (full rewrite, ~900 lines)

## What Was Built

### Layout (single view, fills main area, scrollable)
Root: `<div className="flex h-full flex-col overflow-hidden">` with a sticky `TargetControlBar` on top and a `flex-1 overflow-y-auto` scroll container holding all sections in a `flex flex-col gap-3` stack.

### Sections (top → bottom)
1. **TargetControlBar** — compact horizontal bar:
   - TARGET label + Input (pre-filled `192.168.1.100`, w-200/280px, disabled while active)
   - Select for mode (Demo / Live, disabled while active)
   - START MONITORING (Activity icon, primary cyan) / STOP MONITORING (Square icon, destructive red) button with STARTING…/STOPPING… busy states
   - Inline active status: target address (mono), StatusDot for monitor status, StatusDot for socket connection (LIVE/RECONNECTING), Demo badge
   - AuthWarning on the right (md+)
   - Enter key triggers start
   - `handleStart`: calls `api.startMonitoring(target, mode)` → `useAppStore.startSession(...)` → seeds KPI/network/scenarios via `api.getStatus(sessionId)`. Error mapping: INVALID_TARGET → "Target is unreachable.", START_FAILED → "Initial assessment failed.", UNREACHABLE/no-status → "Unable to connect to monitoring service."
   - `handleStop`: calls `api.stopMonitoring(sessionId)` → `stopSession()` → toast "Monitoring session saved to history." → `resetSession()` after 1s
   - Fallback: uses user-typed target when API session object omits `targetAddress`

2. **AssessmentPanel** (collapsible, shown only when `assessment` exists):
   - Collapsible header with chevron, "INITIAL ASSESSMENT", reachability + open-port count, status badge
   - Two-column grid (lg): TARGET INFORMATION (Target, Reachability, Hostname, OS Guess, Latency, Assessment, Open Ports) | OPEN PORTS & SERVICES (table: Port/Proto/State/Service/Product/Version, port number colored by risk — SSH/RDP amber, HTTP/HTTPS cyan, DBs/FTP/Telnet red, DNS info)
   - Scrollable if >8 ports

3. **KpiGrid** — 9 KpiCard in responsive grid (`grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 xl:grid-cols-9`):
   - EVENTS, CRITICAL (accent critical), HIGH, MEDIUM, LOW, ACTIVE CONNECTIONS, EVENTS/SEC, TRAFFIC KB/s, OPEN PORTS
   - Live pulse dot on EVENTS, ACTIVE CONNS, EVENTS/SEC, TRAFFIC when monitoring active
   - Values from `useAppStore.kpi`; "—" when kpi null

4. **LiveSecurityLog** — Panel titled "LIVE SECURITY LOG":
   - Actions: Pause/Resume (toggles `useAppStore.paused`), Clear View (calls `clearLiveView()` + toast "Live view cleared. History preserved.")
   - Filters: severity toggle badges (All/Critical/High/Medium/Low/Info, colored when active), event-type Select (All + 7 types), search Input (filters source/dest/message)
   - Scrollable table (max-h-[420px], soc-scrollbar): TIME | SOURCE | DESTINATION | PROTOCOL | EVENT | SEVERITY | STATUS
   - TIME = HH:mm:ss (en-GB, mono); SOURCE/DEST = ip:port; PROTOCOL = colored badge; EVENT = eventType + message with DEMO tag (amber) for demo events; SEVERITY = SeverityBadge sm; STATUS = colored dot + text
   - Sticky header, hover highlight, newest-first, capped at 200 rows (useMemo)
   - Empty state: "Waiting for telemetry…" with pulsing cyan dot

5. **LiveNetworkActivity** — Panel titled "LIVE NETWORK ACTIVITY":
   - 4 mini stat boxes at top: Connections, Conn/Sec, Request Rate, Traffic KB/s (with live pulse when active)
   - 2×3 grid of ChartCards (md+):
     - Events/Sec area chart (recharts, cyan, gradient fill, custom tooltip)
     - Traffic Rate area chart (recharts, info-blue, gradient fill)
     - Protocol Distribution bar list (color-coded by protocol)
     - Top Source IPs bar list (top 6, mono labels)
     - Top Destination Ports bar list (top 6, `:port` format)
     - Recent Connections list (last 7, time + src→dst:port + proto badge)
   - Skeleton placeholders when `networkActivity` is null; "No data yet" when chart data empty

6. **LiveAlerts** — Panel titled "LIVE ALERTS":
   - Summary badges in header: CRITICAL/HIGH/MEDIUM/LOW counts (colored)
   - Scrollable list (max-h-[300px], soc-scrollbar) of alert cards (capped at 100):
     - Left accent bar colored by severity
     - Row 1: SeverityBadge + ruleName (bold) + alertId (mono, muted)
     - Row 2: message
     - Row 3: CONF %, recommended action (muted, truncated), timestamp (mono, right-aligned)
   - Empty state: Shield icon + "No alerts. Detection rules are monitoring telemetry…"

### Data Flow
- All live data from `useAppStore` (fed by `useMonitorWs` in page.tsx)
- Individual selectors: `useAppStore((s) => s.field)` for performance
- `useMemo` for filtered events (200 cap), alerts (100 cap), chart data transforms
- `toast` from sonner for all user feedback
- lucide-react icons throughout
- SOC palette only (cyan/low, red/critical, orange/high, amber/medium, green/success, purple/info) — no indigo/blue primary

### Styling
- Dark theme (default), `font-mono-data` for all numbers/IPs/timestamps/IDs
- Compact padding (p-2/p-3, gap-3), information-dense
- `soc-scrollbar` for all scroll regions
- Responsive: 2-col KPI on mobile → 9-col on xl; sections stack on narrow, multi-column on lg+

## Verification Results

### Compile
- `✓ Compiled in 4.2s` — no compile errors

### Lint
- `bun run lint` → 0 errors, 0 warnings in `live-monitor-view.tsx` (20 pre-existing warnings in other files from earlier tasks)

### Agent-Browser E2E (via Caddy gateway http://localhost:81/)
**IMPORTANT:** WS streaming only works through the Caddy gateway (port 81), NOT direct to Next.js (port 3000), because the `XTransformPort=3003` query routing is handled by Caddy. Navigating to `http://localhost:3000/` directly renders the UI but the socket stays on RECONNECTING.

1. **Initial load** (ready state): page renders with sidebar, header "LIVE MONITOR" + "DEMO MODE" badge, TARGET input pre-filled with `192.168.1.100`, START MONITORING button, 9 KPI cards all showing "—", LIVE SECURITY LOG showing "WAITING FOR TELEMETRY…", LIVE ALERTS showing "NO ALERTS…", LIVE NETWORK ACTIVITY showing 4 "—" stats + skeleton chart placeholders. Assessment panel correctly hidden (no assessment yet).

2. **Start monitoring** (click START MONITORING):
   - Button → "STOP MONITORING"; input + select disabled
   - Inline status appears: ACTIVE, target "192.168.1.100", MONITORING status dot, socket LIVE, Demo badge
   - Assessment panel appears (expanded): "INITIAL ASSESSMENT reachable · 3 open ports COMPLETED"
   - Target Information populated: Target=192.168.1.100, Reachability=reachable, Hostname=srv-48, OS Guess=Linux 5.x (Ubuntu 22.04), Latency=4 ms, Assessment=completed, Open Ports=3
   - Open Ports table: 8443/TCP/open/https-alt/Apache Tomcat/9.0.71, 21/TCP/open/ftp/vsftpd/3.0.5, 53/UDP/open/domain/dnsmasq/2.86
   - KPI cards populated via getStatus seed: EVENTS=31, CRITICAL=0, HIGH=0, MEDIUM=10, LOW=0, ACTIVE CONNS=31, EVENTS/SEC=5, TRAFFIC KB/S=0.43, OPEN PORTS=3
   - WS connected (SOCKET: LIVE) — events stream into Live Security Log (port_probe, log_entry, connection events with DEMO tags, severity badges, status dots)
   - Alerts stream into Live Alerts (ALR-cmuhxnu4-NNNNN IDs, severity-colored accent bars, confidence %, recommended actions, timestamps)
   - Network Activity panel populates: Connections=11, Conn/Sec=0.18, Request Rate=0, Traffic KB/s=0.18; Events/Sec + Traffic area charts render (SVG); Protocol Distribution (tcp=13, udp=4); Top Source IPs (172.16.5.8=7, 192.168.1.50=4, ...); Top Dest Ports (:21=9, :8443=4, :53=4); Recent Connections (time + src→dst:port + proto badge)

3. **Filters tested**:
   - Severity filter: clicking CRITICAL → 0 events (correct, no critical); clicking MEDIUM → only MEDIUM-severity rows; clicking ALL → all rows return
   - Pause/Resume: clicking Pause → button changes to "Resume stream"; clicking Resume → back to "Pause"

4. **Stop monitoring** (click STOP MONITORING):
   - Toast: "Monitoring session saved to history."
   - Button reverts to "START MONITORING"
   - Store resets after 1s (input re-enabled, assessment hidden, KPIs back to "—")

### Screenshots
Saved to `/home/z/my-project/agent-ctx/`:
- `initial-load.png` — ready state
- `after-start-fixed.png` — after start (target address fix applied)
- `live-data-streaming.png` — live data flowing through gateway
- `full-dashboard-live.png` — full dashboard with all sections populated

## Remaining Issues / Notes
1. **WS via gateway only**: The `useMonitorWs` hook connects via `io("/?XTransformPort=3003", { path: "/" })` which only works when the browser accesses the app through the Caddy gateway (port 81). Direct access to Next.js (port 3000) renders the UI but the socket cannot connect (Next.js doesn't route the XTransformPort query). This is by design per the environment rules — the Preview Panel exposes the gateway. No code change needed.
2. **API session object omits targetAddress**: The `POST /api/monitoring` response's `session` object does not include `targetAddress` (only `targetId`). The view falls back to the user-typed target (`res.session.targetAddress || t`). This is a backend serialization gap but the frontend handles it gracefully.
3. **Active sessions API returns hostname as targetAddress**: `GET /api/monitoring` returns `targetAddress: "srv-48"` (hostname) rather than the IP. Not used by the LiveMonitor view (which uses the store's targetAddress set at start time), so no impact.
