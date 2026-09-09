import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { LocalFileStore } from "../src/local-store.js";
import { generateEncryptionKey, loadEncryptionKey } from "../src/crypto.js";
import {
  login,
  createAdmin,
  changePassword,
  setRoles,
  setDisabled,
  removeAdmin,
  InvalidCredentialsError,
  AccountLockedError,
  AccountDisabledError,
} from "../src/auth.js";
import { ROLE_SUPERADMIN } from "../src/types.js";
import { CredentialsError } from "../src/errors.js";

let dir: string;
let store: LocalFileStore;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "credentials-test-"));
  const key = loadEncryptionKey("v1", generateEncryptionKey());
  store = new LocalFileStore({
    adminsFilePath: join(dir, "admins.json"),
    auditLogPath: join(dir, "audit-log.jsonl"),
    encryptionKey: key,
  });
});

afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

describe("createAdmin + login", () => {
  it("creates an admin and logs in successfully", async () => {
    await createAdmin(store, { username: "denny", password: "Filipovic12", roles: ["Admin"], actor: "bootstrap" });
    const result = await login(store, "denny", "Filipovic12");
    expect(result.username).toBe("denny");
    expect((result as any).passwordHash).toBeUndefined();
  });

  it("is case-insensitive on username but not on password", async () => {
    await createAdmin(store, { username: "Denny", password: "Filipovic12", roles: ["Admin"], actor: "bootstrap" });
    await expect(login(store, "DENNY", "Filipovic12")).resolves.toBeDefined();
    await expect(login(store, "Denny", "filipovic12")).rejects.toThrow(InvalidCredentialsError);
  });

  it("rejects unknown usernames with a generic error (no user enumeration)", async () => {
    await expect(login(store, "ghost", "whatever12")).rejects.toThrow(InvalidCredentialsError);
  });

  it("allows a temporary password that contains the username when mustChangePassword is set", async () => {
    await createAdmin(store, {
      username: "Linda",
      password: "Passwort_E-Motion-Rennteam-Linda",
      roles: ["Admin"],
      actor: "bootstrap",
      mustChangePassword: true,
    });
    const result = await login(store, "Linda", "Passwort_E-Motion-Rennteam-Linda");
    expect(result.mustChangePassword).toBe(true);
  });

  it("clears mustChangePassword after changePassword", async () => {
    await createAdmin(store, {
      username: "Florian",
      password: "E-Motion-Rennteam-Florian",
      roles: ["Sponsoring-Management"],
      actor: "bootstrap",
      mustChangePassword: true,
    });
    await changePassword(store, { targetUsername: "Florian", newPassword: "NeuesStarkesPw1!", actor: "Florian" });
    const result = await login(store, "Florian", "NeuesStarkesPw1!");
    expect(result.mustChangePassword).toBe(false);
  });
});

describe("lockout", () => {
  it("locks the account after repeated failed attempts", async () => {
    await createAdmin(store, { username: "denny", password: "Filipovic12", roles: ["Admin"], actor: "bootstrap" });

    for (let i = 0; i < 5; i++) {
      await expect(login(store, "denny", "wrong-password")).rejects.toThrow(InvalidCredentialsError);
    }

    await expect(login(store, "denny", "Filipovic12")).rejects.toThrow(AccountLockedError);
  });
});

describe("disable / enable", () => {
  it("prevents login for disabled accounts", async () => {
    await createAdmin(store, { username: "denny", password: "Filipovic12", roles: ["Admin"], actor: "bootstrap" });
    await setDisabled(store, { targetUsername: "denny", disabled: true, actor: "admin" });
    await expect(login(store, "denny", "Filipovic12")).rejects.toThrow(AccountDisabledError);
  });
});

describe("last-superadmin protection", () => {
  it("prevents removing the last superadmin's role", async () => {
    await createAdmin(store, {
      username: "root",
      password: "SuperStarkesPw1!",
      roles: [ROLE_SUPERADMIN],
      actor: "bootstrap",
    });
    await expect(setRoles(store, { targetUsername: "root", roles: ["Admin"], actor: "root" })).rejects.toThrow(
      CredentialsError,
    );
  });

  it("prevents deleting the last superadmin", async () => {
    await createAdmin(store, {
      username: "root",
      password: "SuperStarkesPw1!",
      roles: [ROLE_SUPERADMIN],
      actor: "bootstrap",
    });
    await expect(removeAdmin(store, { targetUsername: "root", actor: "root" })).rejects.toThrow(CredentialsError);
  });

  it("allows removing a superadmin when another one remains", async () => {
    await createAdmin(store, { username: "root1", password: "SuperStarkesPw1!", roles: [ROLE_SUPERADMIN], actor: "bootstrap" });
    await createAdmin(store, { username: "root2", password: "SuperStarkesPw2!", roles: [ROLE_SUPERADMIN], actor: "bootstrap" });
    await expect(removeAdmin(store, { targetUsername: "root1", actor: "root2" })).resolves.toBeUndefined();
  });
});

describe("audit log", () => {
  it("records create, login and password-change events", async () => {
    await createAdmin(store, { username: "denny", password: "Filipovic12", roles: ["Admin"], actor: "bootstrap" });
    await login(store, "denny", "Filipovic12");
    await changePassword(store, { targetUsername: "denny", newPassword: "NochStaerker2!", actor: "denny" });

    const entries = await store.readAuditLog();
    const actions = entries.map((e) => e.action);
    expect(actions).toContain("admin.create");
    expect(actions).toContain("admin.login_success");
    expect(actions).toContain("admin.password_change");
  });

  it("never stores plaintext passwords or hashes in audit metadata", async () => {
    await createAdmin(store, {
      username: "denny",
      password: "Filipovic12",
      roles: ["Admin"],
      actor: "bootstrap",
      mustChangePassword: false,
    });
    const entries = await store.readAuditLog();
    const serialized = JSON.stringify(entries);
    expect(serialized).not.toContain("Filipovic12");
  });
});
