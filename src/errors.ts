export class CredentialsError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = new.target.name;
  }
}

/** Datei existiert im Repo noch nicht (z.B. vor dem Bootstrap). */
export class CredentialsNotFoundError extends CredentialsError {}

/**
 * Optimistic-Concurrency-Konflikt: Die Datei wurde zwischen Lesen und
 * Schreiben von anderer Stelle geaendert (z.B. zwei Browser/Prozesse
 * gleichzeitig). Aufrufer sollte neu laden und Schreibversuch wiederholen.
 */
export class CredentialsConflictError extends CredentialsError {}

/** Entschluesselung fehlgeschlagen: falscher Schluessel oder Datei manipuliert (Auth-Tag-Pruefung fehlgeschlagen). */
export class DecryptionError extends CredentialsError {}

/** Daten entsprechen nicht dem erwarteten Schema (zod-Validierung fehlgeschlagen). */
export class ValidationError extends CredentialsError {}

/** GitHub-API-Fehler nach Ausschoepfen aller Retries (Rate-Limit, Netzwerk, Auth). */
export class GitHubApiError extends CredentialsError {}

/** Passwort erfuellt die Mindestanforderungen nicht. */
export class WeakPasswordError extends CredentialsError {}
