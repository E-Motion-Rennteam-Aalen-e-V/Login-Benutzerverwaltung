import { describe, it, expect, vi, beforeEach } from "vitest";
import { CredentialsClient } from "../src/client.js";
import { generateEncryptionKey, loadEncryptionKey, encryptJson } from "../src/crypto.js";
import { CredentialsConflictError, CredentialsNotFoundError } from "../src/errors.js";
import type { AdminsFile } from "../src/types.js";

/**
 * Minimaler In-Memory-Fake der fuer client.ts relevanten Octokit-Endpunkte.
 * Bildet echtes Git-Verhalten nach: ein Branch zeigt auf einen Commit, ein
 * Commit hat einen Tree + Parents, updateRef schlaegt fehl (422), wenn der
 * neue Commit nicht auf dem aktuellen HEAD aufbaut (Fast-Forward-Check) -
 * genau der Mechanismus, den CredentialsClient fuer Optimistic Concurrency
 * nutzt.
 */
function createFakeOctokit(initialFiles: Record<string, string>) {
  let head = "commit-0";
  let commitCounter = 1;
  let treeCounter = 1;
  let blobCounter = 1;
  const commits: Record<string, { treeSha: string; parents: string[] }> = {
    "commit-0": { treeSha: "tree-0", parents: [] },
  };
  const trees: Record<string, Map<string, string>> = {
    "tree-0": new Map(Object.entries(initialFiles)),
  };
  const blobs: Record<string, string> = {};

  const currentTree = () => trees[commits[head]!.treeSha]!;

  const api = {
    __simulateConcurrentCommit(path: string, content: string) {
      const newTree = new Map(currentTree());
      newTree.set(path, content);
      const treeSha = `tree-${treeCounter++}`;
      trees[treeSha] = newTree;
      const commitSha = `commit-${commitCounter++}`;
      commits[commitSha] = { treeSha, parents: [head] };
      head = commitSha;
    },
    __callCounts: { getRef: 0, updateRef: 0 },
    repos: {
      getContent: vi.fn(async ({ path }: { path: string }) => {
        const content = currentTree().get(path);
        if (content === undefined) {
          const err: any = new Error("Not Found");
          err.status = 404;
          throw err;
        }
        return { data: { content: Buffer.from(content, "utf8").toString("base64"), encoding: "base64" } };
      }),
    },
    git: {
      getRef: vi.fn(async () => {
        api.__callCounts.getRef++;
        return { data: { object: { sha: head } } };
      }),
      getCommit: vi.fn(async ({ commit_sha }: { commit_sha: string }) => ({
        data: { tree: { sha: commits[commit_sha]!.treeSha } },
      })),
      createBlob: vi.fn(async ({ content }: { content: string }) => {
        const sha = `blob-${blobCounter++}`;
        blobs[sha] = Buffer.from(content, "base64").toString("utf8");
        return { data: { sha } };
      }),
      createTree: vi.fn(async ({ base_tree, tree }: { base_tree: string; tree: { path: string; sha: string }[] }) => {
        const newTree = new Map(trees[base_tree]!);
        for (const entry of tree) newTree.set(entry.path, blobs[entry.sha]!);
        const sha = `tree-${treeCounter++}`;
        trees[sha] = newTree;
        return { data: { sha } };
      }),
      createCommit: vi.fn(async ({ tree, parents }: { tree: string; parents: string[] }) => {
        const sha = `commit-${commitCounter++}`;
        commits[sha] = { treeSha: tree, parents };
        return { data: { sha } };
      }),
      updateRef: vi.fn(async ({ sha, force }: { sha: string; force: boolean }) => {
        api.__callCounts.updateRef++;
        const commit = commits[sha]!;
        if (!force && commit.parents[0] !== head) {
          const err: any = new Error("Update is not a fast forward");
          err.status = 422;
          throw err;
        }
        head = sha;
        return { data: {} };
      }),
    },
    getFileAtHead: (path: string) => currentTree().get(path),
  };
  return api;
}

vi.mock("@octokit/rest", () => {
  return { Octokit: vi.fn() };
});

describe("CredentialsClient", () => {
  const key = loadEncryptionKey("v1", generateEncryptionKey());
  const emptyFile: AdminsFile = { schemaVersion: 1, users: [] };

  let fake: ReturnType<typeof createFakeOctokit>;
  let client: CredentialsClient;

  beforeEach(async () => {
    const { Octokit } = await import("@octokit/rest");
    fake = createFakeOctokit({ "admins.json": JSON.stringify(encryptJson(emptyFile, key)) });
    (Octokit as unknown as ReturnType<typeof vi.fn>).mockImplementation(function () {
      return fake;
    });

    client = new CredentialsClient({
      owner: "acme",
      repo: "credentials-repo",
      token: "fake-token",
      encryptionKey: key,
      cacheTtlMs: 0, // Cache im Test deaktivieren, damit jeder Aufruf tatsaechlich die API trifft
    });
  });

  it("loads and decrypts admins.json", async () => {
    const file = await client.loadAdmins();
    expect(file).toEqual(emptyFile);
  });

  it("throws CredentialsNotFoundError when admins.json does not exist", async () => {
    fake = createFakeOctokit({});
    const { Octokit } = await import("@octokit/rest");
    (Octokit as unknown as ReturnType<typeof vi.fn>).mockImplementation(function () {
      return fake;
    });
    client = new CredentialsClient({ owner: "acme", repo: "r", token: "t", encryptionKey: key, cacheTtlMs: 0 });

    await expect(client.loadAdmins()).rejects.toThrow(CredentialsNotFoundError);
  });

  it("writes admins.json + audit-log.jsonl atomically in a single commit", async () => {
    const result = await client.saveAdmins(
      (current) => ({ ...current, users: [{ ...blankUser("denny") }] }),
      { actor: "bootstrap", action: "admin.create", targetUsername: "denny" },
    );

    expect(result.users).toHaveLength(1);
    expect(fake.git.createTree).toHaveBeenCalledTimes(1);
    const treeArg = fake.git.createTree.mock.calls[0]![0];
    const paths = treeArg.tree.map((e: { path: string }) => e.path);
    expect(paths).toEqual(expect.arrayContaining(["admins.json", "audit-log.jsonl"]));

    const auditRaw = fake.getFileAtHead("audit-log.jsonl");
    expect(auditRaw).toBeDefined();
    expect(JSON.parse(auditRaw!.trim())).toMatchObject({ action: "admin.create", targetUsername: "denny" });
  });

  it("retries automatically on a concurrent-write conflict (fast-forward failure)", async () => {
    let firstAttempt = true;
    const originalCreateCommit = fake.git.createCommit.getMockImplementation()!;
    fake.git.createCommit.mockImplementation(async (args: any) => {
      const result = await originalCreateCommit(args);
      if (firstAttempt) {
        firstAttempt = false;
        // Simuliert, dass ein anderer Prozess zwischen unserem getRef() und
        // updateRef() bereits einen Commit gepusht hat.
        fake.__simulateConcurrentCommit("unrelated.txt", "someone else was here");
      }
      return result;
    });

    const result = await client.saveAdmins(
      (current) => ({ ...current, users: [{ ...blankUser("linda") }] }),
      { actor: "bootstrap", action: "admin.create", targetUsername: "linda" },
    );

    expect(result.users).toHaveLength(1);
    expect(fake.__callCounts.getRef).toBeGreaterThanOrEqual(2); // erster Versuch + Retry
    expect(fake.getFileAtHead("unrelated.txt")).toBe("someone else was here"); // fremder Commit blieb erhalten
  });

  it("gives up after maxConflictRetries and throws CredentialsConflictError", async () => {
    client = new CredentialsClient({
      owner: "acme",
      repo: "credentials-repo",
      token: "fake-token",
      encryptionKey: key,
      cacheTtlMs: 0,
      maxConflictRetries: 1,
    });

    const originalCreateCommit = fake.git.createCommit.getMockImplementation()!;
    fake.git.createCommit.mockImplementation(async (args: any) => {
      const result = await originalCreateCommit(args);
      fake.__simulateConcurrentCommit("unrelated.txt", `race-${Math.random()}`);
      return result;
    });

    await expect(
      client.saveAdmins((current) => ({ ...current, users: [{ ...blankUser("racer") }] }), {
        actor: "bootstrap",
        action: "admin.create",
        targetUsername: "racer",
      }),
    ).rejects.toThrow(CredentialsConflictError);
  });
});

function blankUser(username: string) {
  return {
    id: "00000000-0000-4000-8000-000000000000",
    username,
    passwordHash: "$2a$12$C6UzMDM.H6dfI/f/IKcEeO0y3T2ozExYSTqCLQmLZBpz2y3vJ5wZC",
    roles: ["Admin"],
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    createdBy: "bootstrap",
    updatedBy: "bootstrap",
    failedLoginAttempts: 0,
    lockedUntil: null,
    disabled: false,
    mustChangePassword: false,
  };
}
