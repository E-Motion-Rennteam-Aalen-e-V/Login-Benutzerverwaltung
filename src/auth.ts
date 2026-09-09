import { randomUUID } from "node:crypto";
import type { CredentialsStore } from "./store.js";
import type { Admin } from "./types.js";
import { ROLE_SUPERADMIN } from "./types.js";
import { hashPassword, verifyPassword, assertPasswordPolicy, computeLockout } from "./password.js";
import { CredentialsError } from "./errors.js";

export class AccountLockedError extends CredentialsError {}
export class InvalidCredentialsError extends CredentialsError {}
export class AccountDisabledError extends CredentialsError {}

/**
 * Prueft Login-Credentials gegen das Credentials-Repo und pflegt
 * Fehlversuchszaehler/Lockout. Bewusst als einzelne Funktion (nicht Teil von
 * CredentialsClient), damit die Kernbibliothek unabhaengig vom konkreten
 * Login-Flow der konsumierenden App bleibt.
 *
 * Gibt bei Erfolg den Admin OHNE passwordHash zurueck.
 */
export async function login(
  client: CredentialsStore,
  username: string,
  password: string,
): Promise<Omit<Admin, "passwordHash">> {
  const file = await client.loadAdmins({ forceRefresh: true }); // Login IMMER gegen frische Daten pruefen, nie gegen Cache
  const admin = file.users.find((u) => u.username.toLowerCase() === username.toLowerCase());

  // Generische Fehlermeldung bei unbekanntem User (kein User-Enumeration-Leak),
  // aber trotzdem ein bcrypt.compare gegen einen Dummy-Hash, damit die
  // Antwortzeit nicht verraet, ob der Username existiert (Timing-Seitenkanal).
  if (!admin) {
    await verifyPassword(password, DUMMY_HASH);
    throw new InvalidCredentialsError("Benutzername oder Passwort ist falsch.");
  }

  if (admin.disabled) {
    throw new AccountDisabledError("Dieses Konto ist deaktiviert.");
  }

  if (admin.lockedUntil && new Date(admin.lockedUntil).getTime() > Date.now()) {
    throw new AccountLockedError(
      `Konto ist gesperrt bis ${admin.lockedUntil} (zu viele Fehlversuche). Bitte spaeter erneut versuchen.`,
    );
  }

  const valid = await verifyPassword(password, admin.passwordHash);

  if (!valid) {
    const failedLoginAttempts = admin.failedLoginAttempts + 1;
    const { lockedUntil } = computeLockout(failedLoginAttempts);
    await client.saveAdmins(
      (current) => ({
        ...current,
        users: current.users.map((u) =>
          u.id === admin.id ? { ...u, failedLoginAttempts, lockedUntil, updatedAt: new Date().toISOString() } : u,
        ),
      }),
      {
        actor: "system",
        action: lockedUntil ? "admin.lockout" : "admin.login_failure",
        targetUsername: admin.username,
      },
    );
    throw new InvalidCredentialsError("Benutzername oder Passwort ist falsch.");
  }

  // Jeder erfolgreiche Login wird auditiert (Compliance-Anforderung: vollstaendiger
  // Login-Audit-Trail, nicht nur Fehlversuche). Der Datensatz selbst wird nur
  // veraendert, wenn tatsaechlich ein Lockout-Zaehler zurueckzusetzen ist -
  // andernfalls bleibt updatedAt unangetastet, waehrend audit-log.jsonl trotzdem
  // einen neuen Eintrag erhaelt (beides passiert im selben atomaren Commit).
  await client.saveAdmins(
    (current) => ({
      ...current,
      users: current.users.map((u) =>
        u.id === admin.id && (u.failedLoginAttempts > 0 || u.lockedUntil)
          ? { ...u, failedLoginAttempts: 0, lockedUntil: null, updatedAt: new Date().toISOString() }
          : u,
      ),
    }),
    { actor: admin.username, action: "admin.login_success" },
  );

  const { passwordHash: _passwordHash, ...safe } = admin;
  return safe;
}

export interface CreateAdminInput {
  username: string;
  password: string;
  roles: string[];
  actor: string; // Username des ausfuehrenden superadmin
  /** true = Passwort ist ein temporaeres Erstpasswort; Nutzer muss es beim naechsten Login aendern. */
  mustChangePassword?: boolean;
}

/** Legt einen neuen Admin an. Nur von einem bereits authentifizierten superadmin aufzurufen (Autorisierung ist Sache der App-Schicht). */
export async function createAdmin(client: CredentialsStore, input: CreateAdminInput): Promise<Admin> {
  // Bei erzwungenem Erst-Passwortwechsel (mustChangePassword) wird die
  // "Passwort enthaelt Benutzername nicht"-Regel bewusst ausgesetzt: Das
  // Passwort ist per Definition nur fuer den EINEN ersten Login gueltig,
  // alle anderen Regeln (Laenge, Zeichenklassen, Haeufigkeitsliste) gelten
  // weiterhin. Bei aktiver Nutzung (changePassword) bleibt die volle Policy
  // ausnahmslos in Kraft.
  assertPasswordPolicy(input.password, { username: input.mustChangePassword ? undefined : input.username });
  const passwordHash = await hashPassword(input.password);
  const now = new Date().toISOString();

  const newAdmin: Admin = {
    id: randomUUID(),
    username: input.username,
    passwordHash,
    roles: input.roles.length > 0 ? input.roles : ["admin"],
    createdAt: now,
    updatedAt: now,
    createdBy: input.actor,
    updatedBy: input.actor,
    failedLoginAttempts: 0,
    lockedUntil: null,
    disabled: false,
    mustChangePassword: input.mustChangePassword ?? false,
  };

  const result = await client.saveAdmins(
    (current) => {
      if (current.users.some((u) => u.username.toLowerCase() === input.username.toLowerCase())) {
        throw new CredentialsError(`Benutzername "${input.username}" existiert bereits.`);
      }
      return { ...current, users: [...current.users, newAdmin] };
    },
    { actor: input.actor, action: "admin.create", targetUsername: input.username, metadata: { roles: newAdmin.roles } },
  );

  return result.users.find((u) => u.id === newAdmin.id)!;
}

export interface ChangePasswordInput {
  targetUsername: string;
  newPassword: string;
  actor: string;
}

export async function changePassword(client: CredentialsStore, input: ChangePasswordInput): Promise<void> {
  assertPasswordPolicy(input.newPassword, { username: input.targetUsername });
  const passwordHash = await hashPassword(input.newPassword);

  await client.saveAdmins(
    (current) => ({
      ...current,
      users: current.users.map((u) =>
        u.username.toLowerCase() === input.targetUsername.toLowerCase()
          ? {
              ...u,
              passwordHash,
              updatedAt: new Date().toISOString(),
              updatedBy: input.actor,
              failedLoginAttempts: 0,
              lockedUntil: null,
              mustChangePassword: false,
            }
          : u,
      ),
    }),
    { actor: input.actor, action: "admin.password_change", targetUsername: input.targetUsername },
  );
}

export interface SetRolesInput {
  targetUsername: string;
  roles: string[];
  actor: string;
}

export async function setRoles(client: CredentialsStore, input: SetRolesInput): Promise<void> {
  if (input.roles.length === 0) {
    throw new CredentialsError("Mindestens eine Rolle ist erforderlich.");
  }
  await client.saveAdmins(
    (current) => {
      assertLastSuperadminNotRemoved(current.users, input.targetUsername, input.roles);
      return {
        ...current,
        users: current.users.map((u) =>
          u.username.toLowerCase() === input.targetUsername.toLowerCase()
            ? { ...u, roles: input.roles, updatedAt: new Date().toISOString(), updatedBy: input.actor }
            : u,
        ),
      };
    },
    { actor: input.actor, action: "admin.role_change", targetUsername: input.targetUsername, metadata: { roles: input.roles } },
  );
}

export interface SetDisabledInput {
  targetUsername: string;
  disabled: boolean;
  actor: string;
}

export async function setDisabled(client: CredentialsStore, input: SetDisabledInput): Promise<void> {
  await client.saveAdmins(
    (current) => {
      if (input.disabled) {
        assertLastSuperadminNotRemoved(current.users, input.targetUsername, []);
      }
      return {
        ...current,
        users: current.users.map((u) =>
          u.username.toLowerCase() === input.targetUsername.toLowerCase()
            ? { ...u, disabled: input.disabled, updatedAt: new Date().toISOString(), updatedBy: input.actor }
            : u,
        ),
      };
    },
    { actor: input.actor, action: input.disabled ? "admin.disable" : "admin.enable", targetUsername: input.targetUsername },
  );
}

export interface RemoveAdminInput {
  targetUsername: string;
  actor: string;
}

/** Entfernt einen Admin dauerhaft (Hard-Delete). Fuer reversible Sperren siehe setDisabled(). */
export async function removeAdmin(client: CredentialsStore, input: RemoveAdminInput): Promise<void> {
  await client.saveAdmins(
    (current) => {
      assertLastSuperadminNotRemoved(current.users, input.targetUsername, []);
      const exists = current.users.some((u) => u.username.toLowerCase() === input.targetUsername.toLowerCase());
      if (!exists) {
        throw new CredentialsError(`Admin "${input.targetUsername}" existiert nicht.`);
      }
      return { ...current, users: current.users.filter((u) => u.username.toLowerCase() !== input.targetUsername.toLowerCase()) };
    },
    { actor: input.actor, action: "admin.delete", targetUsername: input.targetUsername },
  );
}

/** Verhindert, dass durch Rollen-Aenderung oder Deaktivierung der letzte aktive superadmin verschwindet (Aussperr-Schutz). */
function assertLastSuperadminNotRemoved(users: Admin[], targetUsername: string, newRoles: string[]): void {
  const target = users.find((u) => u.username.toLowerCase() === targetUsername.toLowerCase());
  if (!target || !target.roles.includes(ROLE_SUPERADMIN)) return;

  const willLoseSuperadmin = newRoles.length > 0 ? !newRoles.includes(ROLE_SUPERADMIN) : true;
  if (!willLoseSuperadmin) return;

  const otherActiveSuperadmins = users.filter(
    (u) => u.username.toLowerCase() !== targetUsername.toLowerCase() && u.roles.includes(ROLE_SUPERADMIN) && !u.disabled,
  );
  if (otherActiveSuperadmins.length === 0) {
    throw new CredentialsError(
      `Aktion abgelehnt: "${targetUsername}" ist der letzte aktive superadmin. Es muss mindestens einer verbleiben.`,
    );
  }
}

// Fester, gueltiger bcrypt-Dummy-Hash fuer Timing-Angriffsschutz bei unbekanntem Username (siehe login()).
const DUMMY_HASH = "$2a$12$C6UzMDM.H6dfI/f/IKcEeO0y3T2ozExYSTqCLQmLZBpz2y3vJ5wZC";
