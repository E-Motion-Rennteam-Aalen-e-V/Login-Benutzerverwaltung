export { CredentialsClient } from "./client.js";
export type { CredentialsClientConfig } from "./client.js";

export { LocalFileStore } from "./local-store.js";
export type { LocalFileStoreConfig } from "./local-store.js";
export type { CredentialsStore } from "./store.js";

export {
  loadEncryptionKey,
  generateEncryptionKey,
  encryptJson,
  decryptJson,
} from "./crypto.js";
export type { EncryptionKey } from "./crypto.js";

export {
  hashPassword,
  verifyPassword,
  assertPasswordPolicy,
  computeLockout,
} from "./password.js";

export {
  login,
  createAdmin,
  changePassword,
  setRoles,
  setDisabled,
  removeAdmin,
  AccountLockedError,
  InvalidCredentialsError,
  AccountDisabledError,
} from "./auth.js";
export type {
  CreateAdminInput,
  ChangePasswordInput,
  SetRolesInput,
  SetDisabledInput,
  RemoveAdminInput,
} from "./auth.js";

export { buildAuditEntry, serializeAuditEntries, parseAuditLog } from "./audit.js";
export type { BuildAuditEntryInput } from "./audit.js";

export {
  CredentialsError,
  CredentialsNotFoundError,
  CredentialsConflictError,
  DecryptionError,
  ValidationError,
  GitHubApiError,
  WeakPasswordError,
} from "./errors.js";

export {
  ROLE_SUPERADMIN,
  ROLE_ADMIN,
  ROLE_SPONSORING_MANAGER,
  ROLE_AUDITOR,
  ROLE_CONTENT_MANAGER,
  ROLE_EVENT_MANAGER,
  ROLE_MEMBER_MANAGER,
  ROLE_TREASURER,
  ROLE_OPERATOR,
  ROLE_SPONSORING_VIEWER,
  ROLE_CONTENT_EDITOR,
} from "./types.js";
export type { Admin, AdminsFile, AuditAction, AuditEntry, EncryptedEnvelope } from "./types.js";
