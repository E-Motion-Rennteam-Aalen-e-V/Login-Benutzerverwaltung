import { existsSync, appendFileSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import dotenv from "dotenv";
import { loadEncryptionKey, generateEncryptionKey, type EncryptionKey } from "../../src/crypto.js";
import { CredentialsClient, type CredentialsClientConfig } from "../../src/client.js";
import { LocalFileStore } from "../../src/local-store.js";
import type { CredentialsStore } from "../../src/store.js";

const ENV_PATH = resolve(process.cwd(), ".env");

export function loadEnv(): void {
  dotenv.config({ path: ENV_PATH });
}

/**
 * Liest den Verschluesselungsschluessel aus CREDENTIALS_ENCRYPTION_KEY. Falls
 * nicht gesetzt: generiert EINMALIG einen neuen Schluessel und haengt ihn an
 * die lokale .env an (die per .gitignore NIE ins Repo committet wird), damit
 * er nicht verloren geht. Der Schluessel wird trotzdem klar auf der Konsole
 * ausgegeben, weil er zusaetzlich in den Secret-Store der konsumierenden App
 * uebernommen werden muss (siehe SECURITY.md - der Schluessel lebt bewusst
 * NICHT im GitHub-Repo, sonst waere die Verschluesselung wertlos).
 */
export function resolveEncryptionKey(): EncryptionKey {
  const keyId = process.env.CREDENTIALS_KEY_ID ?? "v1";
  let base64Key = process.env.CREDENTIALS_ENCRYPTION_KEY;

  if (!base64Key) {
    base64Key = generateEncryptionKey();
    persistToEnvFile("CREDENTIALS_ENCRYPTION_KEY", base64Key);
    persistToEnvFile("CREDENTIALS_KEY_ID", keyId);
    // eslint-disable-next-line no-console
    console.warn(
      "\n[credentials] Neuer Verschluesselungsschluessel wurde generiert und in .env gespeichert (NICHT ins Git-Repo committen!).\n" +
        `[credentials] CREDENTIALS_ENCRYPTION_KEY=${base64Key}\n` +
        "[credentials] Diesen Wert zusaetzlich sicher im Secret-Store der App hinterlegen (z.B. Vercel/GitHub Actions Secrets).\n",
    );
  }

  return loadEncryptionKey(keyId, base64Key);
}

function persistToEnvFile(key: string, value: string): void {
  const existing = existsSync(ENV_PATH) ? readFileSync(ENV_PATH, "utf8") : "";
  if (existing.split("\n").some((line) => line.startsWith(`${key}=`))) return;
  appendFileSync(ENV_PATH, `${existing.endsWith("\n") || existing === "" ? "" : "\n"}${key}=${value}\n`);
}

/**
 * Waehlt den Store-Backend automatisch:
 *  - GITHUB_OWNER + GITHUB_REPO + GITHUB_TOKEN gesetzt -> CredentialsClient (echtes GitHub-Repo)
 *  - sonst -> LocalFileStore (admins.json lokal im Projektverzeichnis, fuer Bootstrap
 *    bevor das private Repo existiert)
 */
export function resolveStore(): { store: CredentialsStore; mode: "github" | "local" } {
  return buildStoreWithKey(resolveEncryptionKey());
}

/**
 * Wie resolveStore(), akzeptiert aber einen explizit uebergebenen Schluessel
 * statt ihn aus der Umgebung zu lesen. Wird fuer die Schluesselrotation
 * benoetigt, wo alter und neuer Schluessel gleichzeitig im Spiel sind.
 */
export function buildStoreWithKey(encryptionKey: EncryptionKey): { store: CredentialsStore; mode: "github" | "local" } {
  const owner = process.env.GITHUB_OWNER;
  const repo = process.env.GITHUB_REPO;
  const token = process.env.GITHUB_TOKEN;

  if (owner && repo && token) {
    const config: CredentialsClientConfig = {
      owner,
      repo,
      token,
      branch: process.env.GITHUB_BRANCH ?? "main",
      filePath: process.env.CREDENTIALS_FILE_PATH ?? "admins.json",
      auditLogPath: process.env.CREDENTIALS_AUDIT_LOG_PATH ?? "audit-log.jsonl",
      encryptionKey,
    };
    return { store: new CredentialsClient(config), mode: "github" };
  }

  const store = new LocalFileStore({
    adminsFilePath: resolve(process.cwd(), process.env.CREDENTIALS_FILE_PATH ?? "admins.json"),
    auditLogPath: resolve(process.cwd(), process.env.CREDENTIALS_AUDIT_LOG_PATH ?? "audit-log.jsonl"),
    encryptionKey,
  });
  return { store, mode: "local" };
}
