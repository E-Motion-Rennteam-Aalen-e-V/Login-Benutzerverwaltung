#!/usr/bin/env tsx
/**
 * CLI zum Verwalten von Admin-Benutzern, ohne dass Klartext-Passwoerter
 * jemals in eine Datei geschrieben oder committed werden.
 *
 * Nutzt automatisch GitHub (falls GITHUB_OWNER/REPO/TOKEN gesetzt sind) oder
 * einen lokalen verschluesselten admins.json (fuer den Bootstrap, bevor das
 * private Repo existiert).
 *
 * Beispiele:
 *   tsx scripts/manage-admin.ts add --username Denny --password "..." --roles Admin --actor bootstrap
 *   tsx scripts/manage-admin.ts add --username Linda --password "..." --roles Admin --actor bootstrap --must-change-password
 *   tsx scripts/manage-admin.ts list
 *   tsx scripts/manage-admin.ts remove --username Linda --actor bootstrap --yes
 */
import { loadEnv, resolveStore } from "./lib/env.js";
import { createAdmin, setDisabled, removeAdmin } from "../src/auth.js";
import { WeakPasswordError, CredentialsError } from "../src/errors.js";

loadEnv();

function parseArgs(argv: string[]): { command: string; flags: Record<string, string | boolean> } {
  const [command, ...rest] = argv;
  const flags: Record<string, string | boolean> = {};
  for (let i = 0; i < rest.length; i++) {
    const arg = rest[i];
    if (!arg?.startsWith("--")) continue;
    const key = arg.slice(2);
    const next = rest[i + 1];
    if (next !== undefined && !next.startsWith("--")) {
      flags[key] = next;
      i++;
    } else {
      flags[key] = true;
    }
  }
  return { command: command ?? "", flags };
}

async function main(): Promise<void> {
  const { command, flags } = parseArgs(process.argv.slice(2));
  const { store, mode } = resolveStore();
  // eslint-disable-next-line no-console
  console.log(`[credentials] Backend: ${mode === "github" ? "GitHub-Repo" : "lokale Datei (noch nicht gepusht)"}`);

  switch (command) {
    case "add": {
      const username = requireString(flags, "username");
      const password = requireString(flags, "password");
      const roles = requireString(flags, "roles")
        .split(",")
        .map((r) => r.trim())
        .filter(Boolean);
      const actor = (flags.actor as string) ?? "cli-bootstrap";
      const mustChangePassword = Boolean(flags["must-change-password"]);

      const admin = await createAdmin(store, { username, password, roles, actor, mustChangePassword });
      // eslint-disable-next-line no-console
      console.log(
        `[credentials] Admin "${admin.username}" angelegt. Rollen: ${admin.roles.join(", ")}. ` +
          `Muss Passwort beim naechsten Login aendern: ${admin.mustChangePassword ? "ja" : "nein"}.`,
      );
      if (mode === "local") {
        // eslint-disable-next-line no-console
        console.log(
          "[credentials] Hinweis: Daten liegen lokal in admins.json / audit-log.jsonl. " +
            "Diese Dateien nach Erst-Setup ins private GitHub-Repo committen und pushen (siehe README).",
        );
      }
      break;
    }
    case "disable":
    case "enable": {
      const username = requireString(flags, "username");
      const actor = (flags.actor as string) ?? "cli-operator";
      await setDisabled(store, { targetUsername: username, disabled: command === "disable", actor });
      // eslint-disable-next-line no-console
      console.log(`[credentials] Admin "${username}" wurde ${command === "disable" ? "deaktiviert" : "aktiviert"}.`);
      break;
    }
    case "remove": {
      const username = requireString(flags, "username");
      const actor = (flags.actor as string) ?? "cli-operator";
      if (!flags.yes) {
        throw new CredentialsError(`Hard-Delete ist destruktiv. Zur Bestaetigung --yes anhaengen: remove --username ${username} --yes`);
      }
      await removeAdmin(store, { targetUsername: username, actor });
      // eslint-disable-next-line no-console
      console.log(`[credentials] Admin "${username}" wurde dauerhaft entfernt.`);
      break;
    }
    case "list": {
      const file = await store.loadAdmins({ forceRefresh: true });
      if (file.users.length === 0) {
        // eslint-disable-next-line no-console
        console.log("[credentials] Keine Admins vorhanden.");
        break;
      }
      for (const u of file.users) {
        // eslint-disable-next-line no-console
        console.log(
          `- ${u.username} | Rollen: ${u.roles.join(", ")} | ${u.disabled ? "DEAKTIVIERT" : "aktiv"} | ` +
            `Passwortwechsel erzwungen: ${u.mustChangePassword ? "ja" : "nein"} | ` +
            `gesperrt bis: ${u.lockedUntil ?? "-"}`,
        );
      }
      break;
    }
    default: {
      // eslint-disable-next-line no-console
      console.error(`Unbekannter Befehl: "${command}". Erlaubt: add | disable | enable | remove | list`);
      process.exitCode = 1;
    }
  }
}

function requireString(flags: Record<string, string | boolean>, key: string): string {
  const value = flags[key];
  if (typeof value !== "string" || value.length === 0) {
    throw new CredentialsError(`--${key} ist erforderlich.`);
  }
  return value;
}

main().catch((err) => {
  if (err instanceof WeakPasswordError || err instanceof CredentialsError) {
    // eslint-disable-next-line no-console
    console.error(`[credentials] Fehler: ${err.message}`);
  } else {
    // eslint-disable-next-line no-console
    console.error(err);
  }
  process.exitCode = 1;
});
