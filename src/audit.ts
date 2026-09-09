import type { AuditAction, AuditEntry } from "./types.js";
import { AuditEntrySchema } from "./types.js";
import { ValidationError } from "./errors.js";

export interface BuildAuditEntryInput {
  actor: string;
  action: AuditAction;
  targetUsername?: string;
  metadata?: Record<string, unknown>;
}

/**
 * Baut einen Audit-Eintrag. metadata darf NIEMALS Klartext-Passwoerter oder
 * -Hashes enthalten - Aufrufer sind dafuer verantwortlich, nur unkritische
 * Kontextdaten mitzugeben (z.B. { role: "admin" }, nicht { passwordHash }).
 */
export function buildAuditEntry(input: BuildAuditEntryInput): AuditEntry {
  const entry: AuditEntry = {
    timestamp: new Date().toISOString(),
    actor: input.actor,
    action: input.action,
    ...(input.targetUsername !== undefined ? { targetUsername: input.targetUsername } : {}),
    ...(input.metadata !== undefined ? { metadata: redactSensitiveKeys(input.metadata) } : {}),
  };
  return AuditEntrySchema.parse(entry);
}

const SENSITIVE_KEY_PATTERN = /password|hash|secret|token|key/i;

function redactSensitiveKeys(metadata: Record<string, unknown>): Record<string, unknown> {
  const safe: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(metadata)) {
    safe[key] = SENSITIVE_KEY_PATTERN.test(key) ? "[REDACTED]" : value;
  }
  return safe;
}

/** Serialisiert Audit-Eintraege als JSON-Lines (append-only Log-Format). */
export function serializeAuditEntries(entries: AuditEntry[]): string {
  return entries.map((e) => JSON.stringify(e)).join("\n") + (entries.length > 0 ? "\n" : "");
}

/** Parst ein bestehendes audit-log.jsonl (leerer String -> leeres Array). */
export function parseAuditLog(content: string): AuditEntry[] {
  const lines = content.split("\n").filter((line) => line.trim().length > 0);
  return lines.map((line, idx) => {
    try {
      return AuditEntrySchema.parse(JSON.parse(line));
    } catch (cause) {
      throw new ValidationError(`audit-log.jsonl Zeile ${idx + 1} ist ungueltig: ${String(cause)}`);
    }
  });
}
