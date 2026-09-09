#!/usr/bin/env tsx
/**
 * Rotiert den Verschluesselungsschluessel: entschluesselt admins.json mit dem
 * aktuellen Schluessel (CREDENTIALS_ENCRYPTION_KEY) und verschluesselt es neu
 * mit einem frisch generierten Schluessel unter einer neuen keyId. Danach
 * MUSS der neue Schluessel im Secret-Store der App aktualisiert werden (siehe
 * SECURITY.md, Abschnitt "Schluesselrotation").
 *
 * Usage: npm run rotate-key -- --new-key-id v2
 */
import { loadEnv, resolveEncryptionKey, buildStoreWithKey } from "./lib/env.js";
import { generateEncryptionKey, loadEncryptionKey } from "../src/crypto.js";

loadEnv();

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const idx = args.indexOf("--new-key-id");
  const newKeyId = idx >= 0 ? args[idx + 1] : `v${Date.now()}`;
  if (!newKeyId) throw new Error("--new-key-id benoetigt einen Wert.");

  const oldKey = resolveEncryptionKey();
  if (oldKey.keyId === newKeyId) {
    throw new Error(`Neue keyId "${newKeyId}" ist identisch mit der aktuellen ("${oldKey.keyId}"). Andere ID waehlen.`);
  }

  const { store: oldStore, mode } = buildStoreWithKey(oldKey);
  const current = await oldStore.loadAdmins({ forceRefresh: true });

  const newKeyBase64 = generateEncryptionKey();
  const newKey = loadEncryptionKey(newKeyId, newKeyBase64);
  const { store: newStore } = buildStoreWithKey(newKey);

  await newStore.saveAdmins(() => current, {
    actor: "system",
    action: "key.rotate",
    metadata: { previousKeyId: oldKey.keyId, newKeyId },
  });

  // eslint-disable-next-line no-console
  console.log(
    `\n[credentials] Schluesselrotation abgeschlossen (${mode === "github" ? "GitHub-Repo" : "lokale Datei"}).\n` +
      `[credentials] Neue keyId: ${newKeyId}\n` +
      `[credentials] CREDENTIALS_ENCRYPTION_KEY=${newKeyBase64}\n` +
      `[credentials] CREDENTIALS_KEY_ID=${newKeyId}\n\n` +
      "WICHTIG:\n" +
      "  1. Diese beiden Werte JETZT im Secret-Store der konsumierenden App aktualisieren\n" +
      "     (z.B. Vercel/GitHub Actions Secrets) - erst DANACH ist die App wieder funktionsfaehig.\n" +
      "  2. Den alten Schluessel danach sicher vernichten (aus Passwortmanager/Notizen loeschen).\n" +
      "  3. .env dieses Projekts wurde NICHT automatisch aktualisiert - bei lokaler Weiternutzung manuell anpassen.\n",
  );
}

main().catch((err) => {
  // eslint-disable-next-line no-console
  console.error("[credentials] Rotation fehlgeschlagen:", err);
  process.exitCode = 1;
});
