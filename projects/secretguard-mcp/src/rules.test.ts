import { describe, expect, it } from "vitest";
import { shannonEntropy, isPlaceholderOrReference, ENTROPY_THRESHOLD, buildGenericAssignmentRegex } from "./rules.js";

function matchesVarName(varName: string): boolean {
  const value = "kT9pL2xQ7mV4nW1s"; // 16-char plausible-secret value, well above threshold/length floor
  const regex = buildGenericAssignmentRegex();
  const match = regex.exec(`const ${varName} = "${value}";`);
  return match !== null;
}

describe("shannonEntropy", () => {
  it("returns 0 for an empty string", () => {
    expect(shannonEntropy("")).toBe(0);
  });

  it("returns 0 for a string of a single repeated character", () => {
    expect(shannonEntropy("aaaaaaaaaaaa")).toBe(0);
  });

  it("scores a random-looking mixed-case alphanumeric string above the entropy threshold", () => {
    expect(shannonEntropy("zT9pQ2xR7mK4vL8nW1sD6fH3jC0bA5eY")).toBeGreaterThan(ENTROPY_THRESHOLD);
  });

  it("scores an English-word-like string below the entropy threshold", () => {
    expect(shannonEntropy("passwordpasswordpassword")).toBeLessThan(ENTROPY_THRESHOLD);
  });

  it("increases as character diversity increases", () => {
    expect(shannonEntropy("aabbccdd")).toBeGreaterThan(shannonEntropy("aaaabbbb"));
  });
});

describe("isPlaceholderOrReference", () => {
  it("flags common placeholder values", () => {
    expect(isPlaceholderOrReference("changeme", 'token = "changeme"')).toBe(true);
    expect(isPlaceholderOrReference("xxxxxxxxxxxx", 'key = "xxxxxxxxxxxx"')).toBe(true);
    expect(isPlaceholderOrReference("your-api-key", "")).toBe(true);
  });

  it("flags angle-bracket placeholders", () => {
    expect(isPlaceholderOrReference("<your-token-here>", "")).toBe(true);
  });

  it("flags env-var references regardless of the captured value", () => {
    expect(isPlaceholderOrReference("anything", "token = process.env.API_TOKEN")).toBe(true);
    expect(isPlaceholderOrReference("anything", "token: ${API_TOKEN}")).toBe(true);
    expect(isPlaceholderOrReference("anything", "token = os.environ['API_TOKEN']")).toBe(true);
  });

  it("does not flag a plausible literal secret value", () => {
    expect(isPlaceholderOrReference("zT9pQ2xR7mK4vL8nW1sD6fH3jC0bA5eY", 'token = "zT9pQ2xR7mK4vL8nW1sD6fH3jC0bA5eY"')).toBe(
      false,
    );
  });
});

describe("buildGenericAssignmentRegex variable-name gate", () => {
  it("recognizes common real-world secret-holding *Key compounds", () => {
    for (const name of [
      "sessionKey",
      "signingKey",
      "encryptionKey",
      "masterKey",
      "clientKey",
      "jwtKey",
      "hmacKey",
      "cipherKey",
      "oauthKey",
      "refreshKey",
      "cookieKey",
      "csrfKey",
      "webhookKey",
      "licenseKey",
      "apiKey",
      "accessKey",
      "privateKey",
    ]) {
      expect(matchesVarName(name)).toBe(true);
    }
  });

  it("does not flag common non-secret *Key identifiers (DB/cache/i18n/query shapes)", () => {
    for (const name of [
      "partitionKey",
      "sortKey",
      "cacheKey",
      "idempotencyKey",
      "queryKey",
      "primaryKey",
      "foreignKey",
      "translationKey",
      "localeKey",
      "i18nKey",
      "publicKey",
      "routeKey",
      "indexKey",
    ]) {
      expect(matchesVarName(name)).toBe(false);
    }
  });
});
