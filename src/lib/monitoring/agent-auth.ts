// ============================================================
// LiveSOC - Agent authentication utility (Phase C)
//
// Provides API key hashing + verification for agent auth.
// Keys are stored as SHA-256 hashes (never plaintext).
// ============================================================

import { createHash, randomBytes } from "crypto";

/**
 * Generate a new random API key (returns plaintext key + hash).
 * The plaintext is shown ONCE to the user; only the hash is stored.
 */
export function generateApiKey(): { key: string; hash: string } {
  const key = `lsk_${randomBytes(24).toString("hex")}`;
  const hash = hashApiKey(key);
  return { key, hash };
}

/**
 * Hash an API key for storage. Uses SHA-256.
 */
export function hashApiKey(key: string): string {
  return createHash("sha256").update(key).digest("hex");
}

/**
 * Verify an API key against a stored hash.
 */
export function verifyApiKey(key: string, storedHash: string | null): boolean {
  if (!storedHash) return false;
  return hashApiKey(key) === storedHash;
}

/**
 * Authenticate an agent from request headers.
 * Returns the agent DB row if authenticated, null otherwise.
 *
 * Headers: X-Agent-ID + X-Agent-Key
 */
export async function authenticateAgent(req: Request): Promise<{
  id: string;
  agentId: string;
  hostname: string | null;
  os: string | null;
  status: string;
  enabled: boolean;
} | null> {
  const agentId = req.headers.get("X-Agent-ID");
  const apiKey = req.headers.get("X-Agent-Key");

  if (!agentId || !apiKey) return null;

  const { db } = await import("@/lib/db");
  const agent = await db.agent.findUnique({ where: { agentId } });
  if (!agent) return null;
  if (!agent.enabled) return null;
  if (!verifyApiKey(apiKey, agent.apiKeyHash)) return null;

  return {
    id: agent.id,
    agentId: agent.agentId,
    hostname: agent.hostname,
    os: agent.os,
    status: agent.status,
    enabled: agent.enabled,
  };
}
