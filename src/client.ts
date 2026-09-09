import { Octokit } from "@octokit/rest";
import type { EncryptionKey } from "./crypto.js";
import { encryptJson, decryptJson } from "./crypto.js";
import type { AdminsFile, AuditEntry } from "./types.js";
import { AdminsFileSchema } from "./types.js";
import type { BuildAuditEntryInput } from "./audit.js";
import { buildAuditEntry, serializeAuditEntries, parseAuditLog } from "./audit.js";
import { TtlCache } from "./cache.js";
import type { CredentialsStore } from "./store.js";
import {
  CredentialsConflictError,
  CredentialsNotFoundError,
  GitHubApiError,
  ValidationError,
} from "./errors.js";

export interface CredentialsClientConfig {
  /** GitHub-Owner (User oder Org) des privaten Credentials-Repos. */
  owner: string;
  /** Name des privaten Credentials-Repos. */
  repo: string;
  /**
   * Fine-grained Personal Access Token, beschraenkt auf GENAU dieses Repo
   * mit Contents: Read & Write. Siehe SECURITY.md fuer Scoping-Anleitung.
   */
  token: string;
  branch?: string;
  filePath?: string;
  auditLogPath?: string;
  encryptionKey: EncryptionKey;
  cacheTtlMs?: number;
  maxConflictRetries?: number;
  /** Optionaler Name fuer Commit-Autor (App-Identitaet, nicht der handelnde Admin - der steht im Audit-Eintrag). */
  commitAuthorName?: string;
  commitAuthorEmail?: string;
}

interface ResolvedConfig extends Required<Omit<CredentialsClientConfig, "commitAuthorName" | "commitAuthorEmail">> {
  commitAuthorName: string;
  commitAuthorEmail: string;
}

const RETRYABLE_STATUS = new Set([403, 429, 500, 502, 503, 504]);
const MAX_TRANSIENT_RETRIES = 4;

export class CredentialsClient implements CredentialsStore {
  private readonly octokit: Octokit;
  private readonly cfg: ResolvedConfig;
  private readonly cache: TtlCache<AdminsFile>;

  constructor(config: CredentialsClientConfig) {
    this.cfg = {
      owner: config.owner,
      repo: config.repo,
      token: config.token,
      branch: config.branch ?? "main",
      filePath: config.filePath ?? "admins.json",
      auditLogPath: config.auditLogPath ?? "audit-log.jsonl",
      encryptionKey: config.encryptionKey,
      cacheTtlMs: config.cacheTtlMs ?? 60_000,
      maxConflictRetries: config.maxConflictRetries ?? 3,
      commitAuthorName: config.commitAuthorName ?? "credentials-bot",
      commitAuthorEmail: config.commitAuthorEmail ?? "credentials-bot@users.noreply.github.com",
    };
    this.octokit = new Octokit({ auth: this.cfg.token });
    this.cache = new TtlCache<AdminsFile>(this.cfg.cacheTtlMs);
  }

  /**
   * Laedt die aktuellen Admin-Daten. Nutzt den Cache, sofern nicht
   * force-refresh angefordert wird. Bei GitHub-Ausfall wird - falls
   * verfuegbar - auf veraltete Cache-Daten zurueckgefallen (Fail-Open fuer
   * Lesevorgaenge; Schreibvorgaenge fallen NIE auf Stale-Daten zurueck).
   */
  async loadAdmins(options: { forceRefresh?: boolean } = {}): Promise<AdminsFile> {
    if (!options.forceRefresh) {
      const cached = this.cache.get();
      if (cached) return cached;
    }

    try {
      const file = await this.fetchAndDecryptAdminsFile();
      this.cache.set(file);
      return file;
    } catch (err) {
      const stale = this.cache.getStaleIfAvailable();
      if (stale) {
        // eslint-disable-next-line no-console
        console.warn(
          `[credentials-client] Live-Abruf fehlgeschlagen, verwende zwischengespeicherten Stand (${Math.round(
            stale.ageMs / 1000,
          )}s alt). Grund: ${String(err)}`,
        );
        return stale.value;
      }
      throw err;
    }
  }

  /**
   * Aendert die Admin-Daten atomar. `mutate` erhaelt den JEWEILS FRISCH
   * geladenen Stand (nicht den Cache!) und gibt den neuen Zielzustand
   * zurueck. admins.json UND audit-log.jsonl werden in EINEM Git-Commit
   * geschrieben (Git Data API), sodass nie ein inkonsistenter
   * Zwischenzustand sichtbar wird.
   *
   * Bei gleichzeitigen Schreibzugriffen (z.B. zwei offene CMS-Tabs) wird
   * automatisch bis zu `maxConflictRetries`-mal neu geladen und erneut
   * versucht (Last-Write-Wins mit Re-Validierung, siehe SECURITY.md).
   */
  async saveAdmins(
    mutate: (current: AdminsFile) => AdminsFile,
    auditInput: BuildAuditEntryInput,
  ): Promise<AdminsFile> {
    let lastError: unknown;

    for (let attempt = 0; attempt <= this.cfg.maxConflictRetries; attempt++) {
      const current = await this.fetchAndDecryptAdminsFile();
      const next = mutate(current);
      const parsed = AdminsFileSchema.safeParse(next);
      if (!parsed.success) {
        throw new ValidationError(`Neuer Zustand ist ungueltig: ${parsed.error.message}`);
      }

      const auditEntry = buildAuditEntry(auditInput);

      try {
        await this.commitAtomic(parsed.data, auditEntry);
        this.cache.set(parsed.data);
        return parsed.data;
      } catch (err) {
        if (err instanceof CredentialsConflictError) {
          lastError = err;
          continue; // neu laden und erneut versuchen
        }
        throw err;
      }
    }

    throw new CredentialsConflictError(
      `Schreibvorgang nach ${this.cfg.maxConflictRetries} Versuchen wegen gleichzeitiger Aenderungen fehlgeschlagen.`,
      { cause: lastError },
    );
  }

  async readAuditLog(): Promise<AuditEntry[]> {
    const raw = await this.withRetry(() =>
      this.octokit.repos.getContent({
        owner: this.cfg.owner,
        repo: this.cfg.repo,
        path: this.cfg.auditLogPath,
        ref: this.cfg.branch,
      }),
    ).catch((err) => {
      if (isNotFound(err)) return null;
      throw err;
    });
    if (!raw) return [];
    const content = decodeContent(raw);
    return parseAuditLog(content);
  }

  private async fetchAndDecryptAdminsFile(): Promise<AdminsFile> {
    const raw = await this.withRetry(() =>
      this.octokit.repos.getContent({
        owner: this.cfg.owner,
        repo: this.cfg.repo,
        path: this.cfg.filePath,
        ref: this.cfg.branch,
      }),
    ).catch((err) => {
      if (isNotFound(err)) {
        throw new CredentialsNotFoundError(
          `${this.cfg.filePath} existiert nicht im Repo ${this.cfg.owner}/${this.cfg.repo}@${this.cfg.branch}. ` +
            "Wurde 'npm run bootstrap' bereits ausgefuehrt?",
        );
      }
      throw err;
    });

    const content = decodeContent(raw);
    const envelope: unknown = JSON.parse(content);
    const decrypted = decryptJson<unknown>(envelope, this.cfg.encryptionKey);
    const parsed = AdminsFileSchema.safeParse(decrypted);
    if (!parsed.success) {
      throw new ValidationError(`Entschluesselte Admin-Datei entspricht nicht dem Schema: ${parsed.error.message}`);
    }
    return parsed.data;
  }

  /**
   * Schreibt admins.json + audit-log.jsonl atomar in einem Commit via
   * Git Data API (blobs -> tree -> commit -> ref-update). Der finale
   * `updateRef`-Aufruf ohne `force` schlaegt fehl, wenn sich der Branch seit
   * dem Laden des Basis-Commits bewegt hat (Fast-Forward-Check) - das ist
   * unser Optimistic-Concurrency-Schutz.
   */
  private async commitAtomic(adminsFile: AdminsFile, auditEntry: AuditEntry): Promise<void> {
    const { owner, repo, branch } = this.cfg;

    const refResp = await this.withRetry(() =>
      this.octokit.git.getRef({ owner, repo, ref: `heads/${branch}` }),
    );
    const baseCommitSha = refResp.data.object.sha;

    const baseCommit = await this.withRetry(() =>
      this.octokit.git.getCommit({ owner, repo, commit_sha: baseCommitSha }),
    );
    const baseTreeSha = baseCommit.data.tree.sha;

    const existingAuditLog = await this.withRetry(() =>
      this.octokit.repos.getContent({ owner, repo, path: this.cfg.auditLogPath, ref: branch }),
    ).catch((err) => {
      if (isNotFound(err)) return null;
      throw err;
    });
    const previousAuditContent = existingAuditLog ? decodeContent(existingAuditLog) : "";
    const newAuditContent = previousAuditContent + serializeAuditEntries([auditEntry]);

    const encryptedAdmins = encryptJson(adminsFile, this.cfg.encryptionKey);

    const [adminsBlob, auditBlob] = await Promise.all([
      this.withRetry(() =>
        this.octokit.git.createBlob({
          owner,
          repo,
          content: Buffer.from(JSON.stringify(encryptedAdmins, null, 2), "utf8").toString("base64"),
          encoding: "base64",
        }),
      ),
      this.withRetry(() =>
        this.octokit.git.createBlob({
          owner,
          repo,
          content: Buffer.from(newAuditContent, "utf8").toString("base64"),
          encoding: "base64",
        }),
      ),
    ]);

    const newTree = await this.withRetry(() =>
      this.octokit.git.createTree({
        owner,
        repo,
        base_tree: baseTreeSha,
        tree: [
          { path: this.cfg.filePath, mode: "100644", type: "blob", sha: adminsBlob.data.sha },
          { path: this.cfg.auditLogPath, mode: "100644", type: "blob", sha: auditBlob.data.sha },
        ],
      }),
    );

    const commitMessage = `credentials: ${auditEntry.action} von ${auditEntry.actor}${
      auditEntry.targetUsername ? ` (Ziel: ${auditEntry.targetUsername})` : ""
    }`;

    const newCommit = await this.withRetry(() =>
      this.octokit.git.createCommit({
        owner,
        repo,
        message: commitMessage,
        tree: newTree.data.sha,
        parents: [baseCommitSha],
        author: { name: this.cfg.commitAuthorName, email: this.cfg.commitAuthorEmail },
      }),
    );

    try {
      await this.withRetry(() =>
        this.octokit.git.updateRef({
          owner,
          repo,
          ref: `heads/${branch}`,
          sha: newCommit.data.sha,
          force: false,
        }),
      );
    } catch (err) {
      if (isStatus(err, 422) || isStatus(err, 409)) {
        throw new CredentialsConflictError(
          "Branch wurde zwischenzeitlich von anderer Stelle aktualisiert (Fast-Forward-Check fehlgeschlagen).",
          { cause: err },
        );
      }
      throw err;
    }
  }

  /**
   * Retry mit exponentiellem Backoff + Jitter, ausschliesslich fuer
   * transiente Fehler (Rate-Limits, 5xx, Netzwerk). Alle anderen Fehler
   * (401, 404, 422 ausserhalb des Ref-Updates) werden sofort durchgereicht.
   */
  private async withRetry<T>(fn: () => Promise<T>): Promise<T> {
    let attempt = 0;
    // eslint-disable-next-line no-constant-condition
    while (true) {
      try {
        return await fn();
      } catch (err) {
        attempt++;
        const status = getStatus(err);
        const retryable = status !== undefined && RETRYABLE_STATUS.has(status);

        if (!retryable) {
          // Kein Rate-Limit/5xx (z.B. 404, 401, 422) - unveraendert durchreichen,
          // damit Aufrufer (z.B. isNotFound()) den Original-Status auswerten koennen.
          throw err;
        }
        if (attempt > MAX_TRANSIENT_RETRIES) {
          throw new GitHubApiError(
            `GitHub-API-Aufruf nach ${MAX_TRANSIENT_RETRIES} Versuchen fehlgeschlagen (Status ${status}).`,
            { cause: err },
          );
        }
        const backoffMs = Math.min(8_000, 250 * 2 ** attempt) + Math.random() * 250;
        await sleep(backoffMs);
      }
    }
  }
}

function decodeContent(resp: { data: unknown }): string {
  const data = resp.data as { content?: string; encoding?: string };
  if (!data.content) {
    throw new ValidationError("GitHub-API lieferte keine Datei-Inhalte zurueck (evtl. Verzeichnis statt Datei?).");
  }
  return Buffer.from(data.content, (data.encoding as BufferEncoding) ?? "base64").toString("utf8");
}

function isNotFound(err: unknown): boolean {
  return getStatus(err) === 404;
}

function isStatus(err: unknown, status: number): boolean {
  return getStatus(err) === status;
}

function getStatus(err: unknown): number | undefined {
  if (err && typeof err === "object" && "status" in err) {
    const status = (err as { status: unknown }).status;
    if (typeof status === "number") return status;
  }
  return undefined;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
