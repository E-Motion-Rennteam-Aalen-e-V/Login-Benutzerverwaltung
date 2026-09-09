import { randomBytes, createCipheriv, createDecipheriv, timingSafeEqual } from "node:crypto";
import type { EncryptedEnvelope } from "./types.js";
import { EncryptedEnvelopeSchema } from "./types.js";
import { DecryptionError, ValidationError } from "./errors.js";

const ALGORITHM = "aes-256-gcm" as const;
const IV_LENGTH_BYTES = 12; // empfohlene GCM-IV-Laenge
const KEY_LENGTH_BYTES = 32; // AES-256

export interface EncryptionKey {
  /** Frei waehlbare ID, damit mehrere Schluessel-Generationen unterscheidbar sind (siehe Schluesselrotation in SECURITY.md). */
  keyId: string;
  /** Roh-Schluessel, exakt 32 Bytes. */
  key: Buffer;
}

/**
 * Laedt einen Verschluesselungsschluessel aus einem base64-kodierten String
 * (z.B. aus der Umgebungsvariable CREDENTIALS_ENCRYPTION_KEY). Der Schluessel
 * MUSS mit generateEncryptionKey() bzw. `openssl rand -base64 32` erzeugt
 * worden sein - er wird niemals aus einem Passwort abgeleitet, weil hier
 * volle 256 Bit Entropie zur Verfuegung stehen und eine KDF nur unnoetig
 * Angriffsflaeche (Timing, Parameterwahl) hinzufuegen wuerde.
 */
export function loadEncryptionKey(keyId: string, base64Key: string): EncryptionKey {
  const key = Buffer.from(base64Key, "base64");
  if (key.length !== KEY_LENGTH_BYTES) {
    throw new ValidationError(
      `Encryption key muss ${KEY_LENGTH_BYTES} Bytes (base64-kodiert) lang sein, erhalten: ${key.length} Bytes. ` +
        "Erzeuge einen neuen Schluessel mit: openssl rand -base64 32",
    );
  }
  return { keyId, key };
}

/** Erzeugt einen neuen, kryptographisch sicheren 256-Bit-Schluessel (base64-kodiert). Fuer Bootstrap/Rotation. */
export function generateEncryptionKey(): string {
  return randomBytes(KEY_LENGTH_BYTES).toString("base64");
}

/**
 * Verschluesselt beliebige JSON-serialisierbare Daten zu einem Envelope, wie
 * er 1:1 als admins.json im Repo abgelegt wird. AES-256-GCM liefert
 * Vertraulichkeit UND Integritaet (Auth-Tag) - jede Manipulation am
 * Ciphertext im Git-Verlauf faellt beim Entschluesseln sofort auf.
 */
export function encryptJson(data: unknown, encKey: EncryptionKey): EncryptedEnvelope {
  const iv = randomBytes(IV_LENGTH_BYTES);
  const cipher = createCipheriv(ALGORITHM, encKey.key, iv);
  const plaintext = Buffer.from(JSON.stringify(data), "utf8");
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return {
    envelopeVersion: 1,
    algorithm: ALGORITHM,
    keyId: encKey.keyId,
    iv: iv.toString("base64"),
    authTag: authTag.toString("base64"),
    ciphertext: ciphertext.toString("base64"),
    updatedAt: new Date().toISOString(),
  };
}

/**
 * Entschluesselt einen Envelope. Wirft DecryptionError, wenn der
 * Auth-Tag nicht passt (falscher Schluessel ODER Daten wurden manipuliert)
 * oder wenn keyId nicht mit dem bereitgestellten Schluessel uebereinstimmt.
 */
export function decryptJson<T = unknown>(envelope: unknown, encKey: EncryptionKey): T {
  const parsed = EncryptedEnvelopeSchema.safeParse(envelope);
  if (!parsed.success) {
    throw new ValidationError(`Envelope entspricht nicht dem erwarteten Schema: ${parsed.error.message}`);
  }
  const env = parsed.data;

  if (!constantTimeStringEqual(env.keyId, encKey.keyId)) {
    throw new DecryptionError(
      `Envelope wurde mit Schluessel-ID "${env.keyId}" verschluesselt, bereitgestellt wurde "${encKey.keyId}". ` +
        "Pruefe CREDENTIALS_ENCRYPTION_KEY / CREDENTIALS_KEY_ID oder fuehre eine Schluesselrotation durch.",
    );
  }

  try {
    const decipher = createDecipheriv(ALGORITHM, encKey.key, Buffer.from(env.iv, "base64"));
    decipher.setAuthTag(Buffer.from(env.authTag, "base64"));
    const plaintext = Buffer.concat([
      decipher.update(Buffer.from(env.ciphertext, "base64")),
      decipher.final(),
    ]);
    return JSON.parse(plaintext.toString("utf8")) as T;
  } catch (cause) {
    throw new DecryptionError(
      "Entschluesselung fehlgeschlagen: falscher Schluessel oder Daten wurden manipuliert (Auth-Tag ungueltig).",
      { cause },
    );
  }
}

function constantTimeStringEqual(a: string, b: string): boolean {
  const bufA = Buffer.from(a, "utf8");
  const bufB = Buffer.from(b, "utf8");
  if (bufA.length !== bufB.length) return false;
  return timingSafeEqual(bufA, bufB);
}
