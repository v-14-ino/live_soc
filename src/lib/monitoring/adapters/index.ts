// ============================================================
// LiveSOC - Adapter Registry
//
// Central registry of all telemetry adapters. Each adapter is a
// singleton — the same instance is shared by all callers (API
// routes, the session manager if/when it's wired in, tests).
//
// `getStatusCache()` and `setStatusCache()` provide a process-wide
// 30-second status cache so the GET /api/adapters route doesn't
// hammer `checkAvailability()` on every request.
// ============================================================

import type { AdapterName, AdapterStatus, TelemetryAdapter } from "./base";
import { NmapAdapter } from "./nmap";
import { JournaldAdapter } from "./journald";
import { NginxAdapter } from "./nginx";
import { IptablesAdapter } from "./iptables";
import { SuricataAdapter } from "./suricata";

export type { TelemetryAdapter, AdapterConfig, AdapterHandle, AdapterStatus, AdapterInfo, AdapterMetadata, AdapterName } from "./base";
export { adapterMetadata } from "./base";
export { NmapAdapter } from "./nmap";
export { JournaldAdapter } from "./journald";
export { NginxAdapter } from "./nginx";
export { IptablesAdapter } from "./iptables";
export { SuricataAdapter } from "./suricata";

/** All adapters, keyed by canonical name. */
export const ADAPTER_REGISTRY: Record<AdapterName, TelemetryAdapter> = {
  nmap: new NmapAdapter(),
  journald: new JournaldAdapter(),
  nginx: new NginxAdapter(),
  iptables: new IptablesAdapter(),
  suricata: new SuricataAdapter(),
};

/** Adapters in canonical order (matches registry insertion order). */
export const ADAPTER_LIST: TelemetryAdapter[] = Object.values(ADAPTER_REGISTRY);

/** Look up an adapter by canonical name. */
export function getAdapter(name: string): TelemetryAdapter | undefined {
  return ADAPTER_REGISTRY[name as AdapterName];
}

// ---- in-process status cache (30s TTL) ---------------------

const STATUS_CACHE_TTL_MS = 30_000;

interface CacheEntry {
  status: AdapterStatus;
  expiresAt: number;
}

const statusCache = new Map<AdapterName, CacheEntry>();

/** Returns a non-stale cached status, or undefined. */
export function getStatusCache(name: AdapterName): AdapterStatus | undefined {
  const entry = statusCache.get(name);
  if (!entry) return undefined;
  if (Date.now() > entry.expiresAt) {
    statusCache.delete(name);
    return undefined;
  }
  return entry.status;
}

/** Writes a status into the cache with the standard 30s TTL. */
export function setStatusCache(name: AdapterName, status: AdapterStatus): void {
  statusCache.set(name, { status, expiresAt: Date.now() + STATUS_CACHE_TTL_MS });
}

/** Clears the entire status cache (used by the "Refresh Status" button). */
export function clearStatusCache(): void {
  statusCache.clear();
}

/**
 * Calls `checkAvailability()` on the given adapter and writes the
 * result to the cache. Returns the fresh status. Honours an optional
 * `force` flag to skip the cache.
 */
export async function fetchAdapterStatus(
  adapter: TelemetryAdapter,
  force = false,
): Promise<AdapterStatus> {
  if (!force) {
    const cached = getStatusCache(adapter.name);
    if (cached) return cached;
  }
  let status: AdapterStatus;
  try {
    status = await adapter.checkAvailability();
  } catch (err) {
    // Defensive: checkAvailability() must not throw, but be safe.
    status = {
      available: false,
      reason: `checkAvailability threw: ${err instanceof Error ? err.message : String(err)}`,
      checkedAt: new Date().toISOString(),
    };
  }
  setStatusCache(adapter.name, status);
  return status;
}
