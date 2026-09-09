import { readFile, writeFile, mkdir } from "node:fs/promises";
import { dirname } from "node:path";
import type { EncryptionKey } from "./crypto.js";
import { encryptJson, decryptJson } from "./crypto.js";
import type { AdminsFile, AuditEntry } from "./types.js";
import { AdminsFileSchema } from "./types.js";
import type { BuildAuditEntryInput } from "./audit.js";
import { buildAuditEntry, serializeAuditEntries, parseAuditLog } from "./audit.js";
import type { CredentialsStore } from "./store.js";
import { ValidationError } from "./errors.js";

export interface LocalFileStoreConfig {
  adminsFilePath: string;
  auditLogPath: string;
  encryptionKey: EncryptionKey;
}

/**
 * Dateisystem-basierte Implementierung von CredentialsStore. Gedacht fuer:
 *  - den Bootstrap-Vorgang, BEVOR das private GitHub-Repo angelegt ist
 *  - lokale Entwicklung/Tests ohne GitHub-API-Aufrufe
 *
 * Schreibt admins.json (verschluesselter Envelope) und audit-log.jsonl
 * genauso wie CredentialsClient es spaeter im Git-Commit tut - die Dateien
 * sind 1:1 austauschbar. Nach dem Bootstrap werden sie einmalig ins private
 * Repo committed und gepusht (siehe README "Erst-Setup").
 *
 * KEIN Concurrency-Schutz (kein Aequivalent zum Git-Fast-Forward-Check) -
 * nur fuer Single-Process-CLI-Nutzung gedacht, nicht fuer eine laufende App.
 */
export class LocalFileStore implements CredentialsStore {
  constructor(private readonly cfg: LocalFileStoreConfig) {}

  async loadAdmins(): Promise<AdminsFile> {
    let raw: string;
    try {
      raw = await readFile(this.cfg.adminsFilePath, "utf8");
    } catch {
      return { schemaVersion: 1, users: [] };
    }
    const envelope: unknown = JSON.parse(raw);
    const decrypted = decryptJson<unknown>(envelope, this.cfg.encryptionKey);
    const parsed = AdminsFileSchema.safeParse(decrypted);
    if (!parsed.success) {
      throw new ValidationError(`Lokale admins.json entspricht nicht dem Schema: ${parsed.error.message}`);
    }
    return parsed.data;
  }

  async saveAdmins(
    mutate: (current: AdminsFile) => AdminsFile,
    auditInput: BuildAuditEntryInput,
  ): Promise<AdminsFile> {
    const current = await this.loadAdmins();
    const next = mutate(current);
    const parsed = AdminsFileSchema.safeParse(next);
    if (!parsed.success) {
      throw new ValidationError(`Neuer Zustand ist ungueltig: ${parsed.error.message}`);
    }

    const envelope = encryptJson(parsed.data, this.cfg.encryptionKey);
    await mkdir(dirname(this.cfg.adminsFilePath), { recursive: true });
    await writeFile(this.cfg.adminsFilePath, JSON.stringify(envelope, null, 2) + "\n", "utf8");

    const entry = buildAuditEntry(auditInput);
    await mkdir(dirname(this.cfg.auditLogPath), { recursive: true });
    let previous = "";
    try {
      previous = await readFile(this.cfg.auditLogPath, "utf8");
    } catch {
      // Datei existiert noch nicht - erster Eintrag.
    }
    await writeFile(this.cfg.auditLogPath, previous + serializeAuditEntries([entry]), "utf8");

    return parsed.data;
  }

  async readAuditLog(): Promise<AuditEntry[]> {
    let raw: string;
    try {
      raw = await readFile(this.cfg.auditLogPath, "utf8");
    } catch {
      return [];
    }
    return parseAuditLog(raw);
  }
}
