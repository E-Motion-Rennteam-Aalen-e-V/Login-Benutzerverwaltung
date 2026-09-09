import { describe, it, expect } from "vitest";
import { generateEncryptionKey, loadEncryptionKey, encryptJson, decryptJson } from "../src/crypto.js";
import { DecryptionError, ValidationError } from "../src/errors.js";

describe("crypto", () => {
  it("round-trips arbitrary JSON data", () => {
    const key = loadEncryptionKey("v1", generateEncryptionKey());
    const data = { users: [{ id: "1", name: "Test" }] };

    const envelope = encryptJson(data, key);
    const decrypted = decryptJson(envelope, key);

    expect(decrypted).toEqual(data);
  });

  it("produces no plaintext fields in the envelope", () => {
    const key = loadEncryptionKey("v1", generateEncryptionKey());
    const envelope = encryptJson({ username: "geheim", passwordHash: "geheim-hash" }, key);
    const serialized = JSON.stringify(envelope);

    expect(serialized).not.toContain("geheim");
  });

  it("throws DecryptionError when the wrong key is used", () => {
    const keyA = loadEncryptionKey("v1", generateEncryptionKey());
    const keyB = loadEncryptionKey("v1", generateEncryptionKey());
    const envelope = encryptJson({ secret: true }, keyA);

    expect(() => decryptJson(envelope, keyB)).toThrow(DecryptionError);
  });

  it("throws DecryptionError when the ciphertext is tampered with", () => {
    const key = loadEncryptionKey("v1", generateEncryptionKey());
    const envelope = encryptJson({ secret: true }, key);
    const tampered = { ...envelope, ciphertext: Buffer.from("tampered-data").toString("base64") };

    expect(() => decryptJson(tampered, key)).toThrow(DecryptionError);
  });

  it("throws DecryptionError on keyId mismatch (rotation safety)", () => {
    const key = loadEncryptionKey("v1", generateEncryptionKey());
    const envelope = encryptJson({ secret: true }, key);
    const wrongIdKey = loadEncryptionKey("v2", Buffer.from(key.key).toString("base64"));

    expect(() => decryptJson(envelope, wrongIdKey)).toThrow(DecryptionError);
  });

  it("rejects encryption keys that are not exactly 32 bytes", () => {
    expect(() => loadEncryptionKey("v1", Buffer.from("too-short").toString("base64"))).toThrow(ValidationError);
  });

  it("rejects malformed envelopes", () => {
    const key = loadEncryptionKey("v1", generateEncryptionKey());
    expect(() => decryptJson({ not: "an envelope" }, key)).toThrow(ValidationError);
  });
});
