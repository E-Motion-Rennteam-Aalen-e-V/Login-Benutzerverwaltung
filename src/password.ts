import bcrypt from "bcryptjs";
import { WeakPasswordError } from "./errors.js";

/**
 * Bcrypt-Cost-Faktor. 12 ist 2026 ein vernuenftiger Default (~250ms auf
 * moderner Hardware) - hoch genug um Offline-Bruteforce zu verteuern, ohne
 * Login-Latenz spuerbar zu erhoehen. Bei Bedarf ueber Env ueberschreibbar,
 * damit die Kosten mit steigender Hardware-Leistung mitwachsen koennen.
 */
const DEFAULT_COST_FACTOR = 12;

const MIN_LENGTH = 11;

// Sehr haeufige/triviale Passwoerter, die trotz Laenge sofort abgelehnt werden.
// Ersetzt keine vollstaendige Breach-Liste, faengt aber die offensichtlichsten Faelle ab.
const COMMON_PASSWORDS = new Set([
  "password123!",
  "passwort123!",
  "admin1234567",
  "qwertzuiop12",
  "qwertyuiop12",
  "letmein12345",
  "changeme1234",
  "superadmin123",
]);

export async function hashPassword(plain: string, costFactor = DEFAULT_COST_FACTOR): Promise<string> {
  const salt = await bcrypt.genSalt(costFactor);
  return bcrypt.hash(plain, salt);
}

export async function verifyPassword(plain: string, hash: string): Promise<boolean> {
  return bcrypt.compare(plain, hash);
}

export interface PasswordPolicyOptions {
  username?: string | undefined;
  minLength?: number;
}

/**
 * Prueft Mindestanforderungen an ein neues Passwort. Wirft WeakPasswordError
 * mit einer fuer Endnutzer verstaendlichen Begruendung statt eines generischen
 * Fehlers, damit das CMS-Panel die Meldung direkt anzeigen kann.
 */
export function assertPasswordPolicy(plain: string, options: PasswordPolicyOptions = {}): void {
  const minLength = options.minLength ?? MIN_LENGTH;

  if (plain.length < minLength) {
    throw new WeakPasswordError(`Passwort muss mindestens ${minLength} Zeichen lang sein.`);
  }
  if (plain.length > 128) {
    // Schuetzt bcrypt (das nach 72 Bytes ohnehin abschneidet) und die API vor
    // absichtlich riesigen Eingaben (Denial-of-Service via teurer Hash-Berechnung).
    throw new WeakPasswordError("Passwort darf maximal 128 Zeichen lang sein.");
  }

  const categories = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^a-zA-Z0-9]/];
  const matched = categories.filter((re) => re.test(plain)).length;
  if (matched < 3) {
    throw new WeakPasswordError(
      "Passwort muss mindestens 3 der 4 Zeichenklassen enthalten: Kleinbuchstaben, Grossbuchstaben, Ziffern, Sonderzeichen.",
    );
  }

  if (COMMON_PASSWORDS.has(plain.toLowerCase())) {
    throw new WeakPasswordError("Dieses Passwort ist zu haeufig / leicht zu erraten. Bitte ein anderes waehlen.");
  }

  if (options.username && plain.toLowerCase().includes(options.username.toLowerCase())) {
    throw new WeakPasswordError("Passwort darf den Benutzernamen nicht enthalten.");
  }
}

/** Login-Lockout-Policy: nach wie vielen Fehlversuchen wie lange gesperrt wird. Exponentiell, um Bruteforce zu verlangsamen. */
export function computeLockout(failedAttempts: number): { lockedUntil: string | null } {
  const THRESHOLD = 5;
  if (failedAttempts < THRESHOLD) return { lockedUntil: null };

  const extraAttempts = failedAttempts - THRESHOLD;
  const minutes = Math.min(60, 2 ** extraAttempts); // 1min, 2min, 4min, ... gedeckelt bei 60min
  const lockedUntil = new Date(Date.now() + minutes * 60_000).toISOString();
  return { lockedUntil };
}
