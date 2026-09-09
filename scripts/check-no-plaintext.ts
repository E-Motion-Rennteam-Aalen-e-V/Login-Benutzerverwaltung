#!/usr/bin/env tsx
/**
 * CI-Sicherheitsgate: stellt sicher, dass admins.json IMMER ausschliesslich
 * dem verschluesselten Envelope-Schema entspricht (keine zusaetzlichen,
 * potenziell im Klartext hinzugefuegten Felder wie "username" oder
 * "passwordHash" auf oberster Ebene) und dass audit-log.jsonl keine
 * sensiblen Schluesselnamen in metadata enthaelt.
 *
 * Zweck: Falls jemand aus Versehen (z.B. per Copy-Paste oder manuellem
 * Edit) Klartext-Zugangsdaten committet, bricht die CI-Pipeline SOFORT ab,
 * statt dass es unbemerkt in der Git-Historie landet.
 */
import { readFile } from "node:fs/promises";
import { EncryptedEnvelopeSchema } from "../src/types.js";

const ADMINS_PATH = process.env.CREDENTIALS_FILE_PATH ?? "admins.json";
const AUDIT_PATH = process.env.CREDENTIALS_AUDIT_LOG_PATH ?? "audit-log.jsonl";
const SENSITIVE_KEY_PATTERN = /password|hash|secret|token|key/i;

async function main(): Promise<void> {
  let failed = false;

  try {
    const raw = await readFile(ADMINS_PATH, "utf8");
    const parsed = JSON.parse(raw);

    // .strict() lehnt JEDES zusaetzliche Feld ab - genau das ist hier gewollt.
    const result = EncryptedEnvelopeSchema.strict().safeParse(parsed);
    if (!result.success) {
      failed = true;
      // eslint-disable-next-line no-console
      console.error(
        `[check-no-plaintext] ${ADMINS_PATH} entspricht NICHT dem erwarteten verschluesselten Envelope-Format:\n` +
          result.error.issues.map((i) => `  - ${i.path.join(".")}: ${i.message}`).join("\n") +
          "\n\nMoegliche Ursache: Klartext-Zugangsdaten wurden versehentlich committet. NICHT pushen/mergen, " +
          "sondern den Commit entfernen und admins.json ausschliesslich ueber die Bibliothek/CLI schreiben.",
      );
    }
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") {
      failed = true;
      // eslint-disable-next-line no-console
      console.error(`[check-no-plaintext] Konnte ${ADMINS_PATH} nicht lesen/parsen:`, err);
    }
  }

  try {
    const raw = await readFile(AUDIT_PATH, "utf8");
    const lines = raw.split("\n").filter((l) => l.trim().length > 0);
    lines.forEach((line, idx) => {
      const entry = JSON.parse(line);
      const metadataKeys = Object.keys(entry.metadata ?? {});
      const leaked = metadataKeys.filter((k) => SENSITIVE_KEY_PATTERN.test(k) && entry.metadata[k] !== "[REDACTED]");
      if (leaked.length > 0) {
        failed = true;
        // eslint-disable-next-line no-console
        console.error(
          `[check-no-plaintext] ${AUDIT_PATH} Zeile ${idx + 1}: unredaktierte sensible Metadaten-Keys: ${leaked.join(", ")}`,
        );
      }
    });
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") {
      failed = true;
      // eslint-disable-next-line no-console
      console.error(`[check-no-plaintext] Konnte ${AUDIT_PATH} nicht lesen/parsen:`, err);
    }
  }

  if (failed) {
    process.exitCode = 1;
  } else {
    // eslint-disable-next-line no-console
    console.log("[check-no-plaintext] OK: keine Klartext-Zugangsdaten gefunden.");
  }
}

main();
