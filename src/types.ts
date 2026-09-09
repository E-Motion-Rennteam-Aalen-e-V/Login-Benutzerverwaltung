import { z } from "zod";

/**
 * Rollen sind bewusst als offene Strings modelliert (nicht als starres Enum),
 * damit die konsumierende App eigene Rollen einfuehren kann, ohne dieses
 * Paket zu aendern. "superadmin" ist die einzige Rolle mit Sonderbedeutung:
 * nur superadmin darf ueber die API andere Admins verwalten.
 */
export const ROLE_SUPERADMIN = "superadmin" as const;

export const RoleSchema = z.string().min(1).max(64);

export const AdminSchema = z.object({
  id: z.string().uuid(),
  username: z
    .string()
    .min(3)
    .max(64)
    .regex(/^[a-zA-Z0-9._-]+$/, "Username darf nur a-z, A-Z, 0-9, '.', '_', '-' enthalten"),
  passwordHash: z.string().min(20), // bcrypt-Hash, nie Klartext
  roles: z.array(RoleSchema).min(1),
  createdAt: z.string().datetime(),
  updatedAt: z.string().datetime(),
  createdBy: z.string().min(1),
  updatedBy: z.string().min(1),
  failedLoginAttempts: z.number().int().min(0).default(0),
  lockedUntil: z.string().datetime().nullable().default(null),
  disabled: z.boolean().default(false),
  /** Erzwingt Passwortwechsel beim naechsten Login (z.B. nach Erstanlage mit temporaerem Passwort). */
  mustChangePassword: z.boolean().default(false),
});
export type Admin = z.infer<typeof AdminSchema>;

export const AdminsFileSchema = z.object({
  schemaVersion: z.literal(1),
  users: z.array(AdminSchema),
});
export type AdminsFile = z.infer<typeof AdminsFileSchema>;

/**
 * Verschluesselter Umschlag, wie er tatsaechlich als admins.json im Repo liegt.
 * Enthaelt NIE Klartext-Nutzerdaten - nur AES-256-GCM-Ciphertext + Metadaten.
 */
export const EncryptedEnvelopeSchema = z.object({
  envelopeVersion: z.literal(1),
  algorithm: z.literal("aes-256-gcm"),
  keyId: z.string().min(1), // erlaubt Schluesselrotation ohne Ambiguitaet
  iv: z.string().min(1), // base64
  authTag: z.string().min(1), // base64
  ciphertext: z.string().min(1), // base64
  updatedAt: z.string().datetime(),
});
export type EncryptedEnvelope = z.infer<typeof EncryptedEnvelopeSchema>;

export const AuditActionSchema = z.enum([
  "admin.create",
  "admin.update",
  "admin.password_change",
  "admin.role_change",
  "admin.disable",
  "admin.enable",
  "admin.delete",
  "admin.login_success",
  "admin.login_failure",
  "admin.lockout",
  "key.rotate",
]);
export type AuditAction = z.infer<typeof AuditActionSchema>;

export const AuditEntrySchema = z.object({
  timestamp: z.string().datetime(),
  actor: z.string().min(1), // Username oder "system"
  action: AuditActionSchema,
  targetUsername: z.string().optional(),
  metadata: z.record(z.unknown()).optional(),
});
export type AuditEntry = z.infer<typeof AuditEntrySchema>;
