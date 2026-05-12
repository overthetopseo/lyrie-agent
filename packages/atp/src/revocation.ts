/**
 * revocation.ts — Certificate Revocation.
 *
 * ATP v2: CRL-style revocation for agent certificates and delegation certs.
 * IETF ATP Draft §7.1 — Revocation
 *
 * Design notes:
 *   - RevocationList is a signed, append-only log (like a mini CRL).
 *   - The list signature covers the canonical JSON of `entries` only, so the
 *     issuer can be changed without re-signing; in practice you'd re-issue.
 *   - `addRevocation` returns a new list (immutable update pattern).
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { canonicalize, signCanonical, verifyCanonical, newUuid } from "./crypto";

// ─── Types ───────────────────────────────────────────────────────────────────

export type RevocationReason =
  | "key_compromise"
  | "agent_compromised"
  | "scope_violation"
  | "expired"
  | "superseded"
  | "unspecified";

export interface RevocationEntry {
  /** Certificate ID (AIC cert-id, delegation cert id, etc.) */
  certId: string;
  /** ISO 8601 */
  revokedAt: string;
  reason: RevocationReason;
  /** Agent ID of the revoker (authoritative entity). */
  revokedBy: string;
}

export interface RevocationList {
  /** Agent/org ID of the CRL issuer. */
  issuer: string;
  /** ISO 8601 — when this CRL was created or last updated. */
  issuedAt: string;
  entries: RevocationEntry[];
  /** Ed25519 signature (base64) over canonicalize({ entries }). */
  signature: string;
}

// ─── Create ──────────────────────────────────────────────────────────────────

/**
 * Create a new RevocationList from a set of initial entries.
 *
 * The signature covers `{ entries }` only so consumers can verify just the
 * entries without caring about the mutable metadata fields.
 */
export function createRevocationList(
  entries: Omit<RevocationEntry, "revokedAt">[],
  issuerKeyPair: { privateKey: string; issuerAgentId?: string },
): RevocationList {
  const now = new Date().toISOString();
  const fullEntries: RevocationEntry[] = entries.map((e) => ({
    ...e,
    revokedAt: now,
  }));

  const signature = signCanonical({ entries: fullEntries }, issuerKeyPair.privateKey);

  return {
    issuer: issuerKeyPair.issuerAgentId ?? "unknown",
    issuedAt: now,
    entries: fullEntries,
    signature,
  };
}

// ─── Verify ──────────────────────────────────────────────────────────────────

/**
 * Verify the RevocationList's own signature before trusting its entries.
 * Always call this before calling isRevoked() in production.
 *
 * @param crl              The revocation list to verify.
 * @param issuerPublicKey  Ed25519 public key (base64) of the expected issuer.
 */
export function verifyRevocationList(
  crl: RevocationList,
  issuerPublicKey: string,
): { valid: boolean; reason?: string } {
  try {
    const ok = verifyCanonical({ entries: crl.entries }, issuerPublicKey, crl.signature);
    if (!ok) return { valid: false, reason: "revocation list signature is invalid" };
    return { valid: true };
  } catch (e) {
    return { valid: false, reason: `revocation list verification threw: ${e}` };
  }
}

// ─── Query ───────────────────────────────────────────────────────────────────

/**
 * Returns true iff `certId` appears in the revocation list.
 * NOTE: Always call verifyRevocationList() first to ensure the CRL is authentic.
 */
export function isRevoked(certId: string, crl: RevocationList): boolean {
  return crl.entries.some((e) => e.certId === certId);
}

// ─── Append ──────────────────────────────────────────────────────────────────

/**
 * Add a revocation entry and re-sign. Returns a new RevocationList
 * (the original is not mutated).
 */
export function addRevocation(
  crl: RevocationList,
  entry: Omit<RevocationEntry, "revokedAt">,
  issuerKeyPair: { privateKey: string; issuerAgentId?: string },
): RevocationList {
  const newEntry: RevocationEntry = {
    ...entry,
    revokedAt: new Date().toISOString(),
  };
  const newEntries = [...crl.entries, newEntry];
  const signature = signCanonical({ entries: newEntries }, issuerKeyPair.privateKey);

  return {
    issuer: issuerKeyPair.issuerAgentId ?? crl.issuer,
    issuedAt: new Date().toISOString(),
    entries: newEntries,
    signature,
  };
}
