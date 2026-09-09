import type { AdminsFile, AuditEntry } from "./types.js";
import type { BuildAuditEntryInput } from "./audit.js";

/**
 * Gemeinsames Interface fuer CredentialsClient (GitHub-Backend, Produktion)
 * und LocalFileStore (Dateisystem-Backend, Bootstrap/lokale Entwicklung
 * bevor das private GitHub-Repo existiert). auth.ts (login/createAdmin/...)
 * ist bewusst gegen dieses Interface geschrieben, nicht gegen eine konkrete
 * Implementierung, damit dieselbe Logik in beiden Modi funktioniert.
 */
export interface CredentialsStore {
  loadAdmins(options?: { forceRefresh?: boolean }): Promise<AdminsFile>;
  saveAdmins(
    mutate: (current: AdminsFile) => AdminsFile,
    auditInput: BuildAuditEntryInput,
  ): Promise<AdminsFile>;
  readAuditLog(): Promise<AuditEntry[]>;
}
