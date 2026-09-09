import { describe, it, expect } from "vitest";
import { hashPassword, verifyPassword, assertPasswordPolicy, computeLockout } from "../src/password.js";
import { WeakPasswordError } from "../src/errors.js";

describe("password hashing", () => {
  it("hashes and verifies correctly", async () => {
    const hash = await hashPassword("KorrektesPasswort1!");
    expect(hash).not.toContain("KorrektesPasswort1!");
    expect(await verifyPassword("KorrektesPasswort1!", hash)).toBe(true);
    expect(await verifyPassword("FalschesPasswort", hash)).toBe(false);
  });

  it("produces a different hash each time (random salt)", async () => {
    const a = await hashPassword("KorrektesPasswort1!");
    const b = await hashPassword("KorrektesPasswort1!");
    expect(a).not.toEqual(b);
  });
});

describe("password policy", () => {
  it("accepts a strong password", () => {
    expect(() => assertPasswordPolicy("Filipovic12", { username: "denny" })).not.toThrow();
  });

  it("rejects passwords shorter than the minimum length", () => {
    expect(() => assertPasswordPolicy("Ab1!")).toThrow(WeakPasswordError);
  });

  it("rejects passwords with fewer than 3 character classes", () => {
    expect(() => assertPasswordPolicy("nurkleinbuchstaben")).toThrow(WeakPasswordError);
  });

  it("rejects passwords containing the username", () => {
    expect(() => assertPasswordPolicy("dennyIstDerBeste1", { username: "denny" })).toThrow(WeakPasswordError);
  });

  it("rejects common passwords", () => {
    expect(() => assertPasswordPolicy("Passwort123!")).toThrow(WeakPasswordError);
  });

  it("rejects passwords over the max length (DoS guard)", () => {
    expect(() => assertPasswordPolicy("A1!".repeat(50))).toThrow(WeakPasswordError);
  });
});

describe("lockout policy", () => {
  it("does not lock out below the threshold", () => {
    expect(computeLockout(4).lockedUntil).toBeNull();
  });

  it("locks out at and above the threshold with growing duration", () => {
    const first = computeLockout(5);
    const second = computeLockout(6);
    expect(first.lockedUntil).not.toBeNull();
    expect(second.lockedUntil).not.toBeNull();
    expect(new Date(second.lockedUntil!).getTime()).toBeGreaterThan(new Date(first.lockedUntil!).getTime());
  });
});
