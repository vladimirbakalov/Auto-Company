import { afterEach, describe, expect, it, vi } from "vitest";
import Anthropic from "@anthropic-ai/sdk";
import { triageCandidates, parseTriageResponse, buildTriagePayload, toSafeTriageError } from "./triage";
import type { Finding } from "./scan";

const SECRET = "zT9pQ2xR7mK4vL8nW1sD6fH3jC0bA5eY";
const API_KEY = "sk-ant-super-secret-test-key-do-not-leak";

function genericFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    filename: "src/config.ts",
    line: 12,
    ruleId: "generic-high-entropy-secret",
    description: 'High-entropy value assigned to "apiToken"',
    confidence: "generic",
    secret: SECRET,
    contextLine: `const apiToken = "${SECRET}";`,
    ...overrides,
  };
}

describe("buildTriagePayload", () => {
  it("never includes the raw secret value, only a masked form", () => {
    const payload = buildTriagePayload([{ id: 0, finding: genericFinding() }]);
    const serialized = JSON.stringify(payload);
    expect(serialized).not.toContain(SECRET);
    expect(payload[0].maskedValue).not.toBe(SECRET);
  });

  it("includes enough shape for the model to reason about plausibility", () => {
    const payload = buildTriagePayload([{ id: 0, finding: genericFinding() }]);
    expect(payload[0].valueLength).toBe(SECRET.length);
    expect(payload[0].entropyBitsPerChar).toBeGreaterThan(0);
    expect(payload[0].maskedContextLine).not.toContain(SECRET);
  });
});

describe("parseTriageResponse", () => {
  it("parses a well-formed JSON array response", () => {
    const result = parseTriageResponse('[{"id": 0, "isLikelySecret": false}, {"id": 1, "isLikelySecret": true}]');
    expect(result.get(0)).toBe(false);
    expect(result.get(1)).toBe(true);
  });

  it("extracts the JSON array even if the model wraps it in prose or a code fence", () => {
    const result = parseTriageResponse('Here you go:\n```json\n[{"id": 0, "isLikelySecret": false}]\n```');
    expect(result.get(0)).toBe(false);
  });

  it("returns an empty map for unparseable text rather than throwing", () => {
    const result = parseTriageResponse("not json at all");
    expect(result.size).toBe(0);
  });

  it("ignores malformed entries in an otherwise valid array", () => {
    const result = parseTriageResponse('[{"id": "not-a-number", "isLikelySecret": true}, {"id": 2, "isLikelySecret": false}]');
    expect(result.has(0)).toBe(false);
    expect(result.get(2)).toBe(false);
  });
});

describe("triageCandidates", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("keeps candidates the model marks as likely secrets, drops the rest", async () => {
    vi.spyOn(Anthropic.Messages.prototype, "create").mockResolvedValue({
      content: [{ type: "text", text: '[{"id": 0, "isLikelySecret": true}, {"id": 1, "isLikelySecret": false}]' }],
    } as Anthropic.Message);

    const result = await triageCandidates({
      apiKey: API_KEY,
      model: "claude-opus-4-8",
      candidates: [
        { id: 0, finding: genericFinding() },
        { id: 1, finding: genericFinding({ line: 20 }) },
      ],
    });

    expect(result.get(0)).toBe(true);
    expect(result.get(1)).toBe(false);
  });

  it("fails safe: keeps a candidate flagged if the model response never addresses its id", async () => {
    vi.spyOn(Anthropic.Messages.prototype, "create").mockResolvedValue({
      content: [{ type: "text", text: '[{"id": 0, "isLikelySecret": false}]' }],
    } as Anthropic.Message);

    const result = await triageCandidates({
      apiKey: API_KEY,
      model: "claude-opus-4-8",
      candidates: [
        { id: 0, finding: genericFinding() },
        { id: 1, finding: genericFinding({ line: 20 }) },
      ],
    });

    expect(result.get(1)).toBe(true); // never addressed -> fail safe, stays flagged
  });

  it("fails safe: keeps everything flagged when the API call throws", async () => {
    vi.spyOn(Anthropic.Messages.prototype, "create").mockRejectedValue(new Error("network exploded"));

    await expect(
      triageCandidates({
        apiKey: API_KEY,
        model: "claude-opus-4-8",
        candidates: [{ id: 0, finding: genericFinding() }],
      }),
    ).rejects.toThrow();
  });

  it("returns an empty map immediately when there are no candidates (no API call made)", async () => {
    const spy = vi.spyOn(Anthropic.Messages.prototype, "create");
    const result = await triageCandidates({ apiKey: API_KEY, model: "claude-opus-4-8", candidates: [] });

    expect(result.size).toBe(0);
    expect(spy).not.toHaveBeenCalled();
  });

  it("never sends more than the per-run candidate cap, and fails safe on the overflow", async () => {
    const spy = vi.spyOn(Anthropic.Messages.prototype, "create").mockResolvedValue({
      content: [{ type: "text", text: "[]" }],
    } as unknown as Anthropic.Message);

    const candidates = Array.from({ length: 45 }, (_, i) => ({ id: i, finding: genericFinding({ line: i }) }));
    const result = await triageCandidates({ apiKey: API_KEY, model: "claude-opus-4-8", candidates });

    const [request] = spy.mock.calls[0];
    const sentPayload = JSON.parse(request.messages[0].content as string) as Array<{ id: number }>;
    expect(sentPayload.length).toBeLessThanOrEqual(30);
    expect(result.get(44)).toBe(true); // overflow candidate never sent, fails safe as flagged
  });

  it("never leaks the API key even if the underlying SDK error happens to contain it", async () => {
    vi.spyOn(Anthropic.Messages.prototype, "create").mockRejectedValue(
      new Anthropic.AuthenticationError(401, { error: { message: `invalid key ${API_KEY}` } }, `invalid key ${API_KEY}`, new Headers()),
    );

    await expect(
      triageCandidates({ apiKey: API_KEY, model: "claude-opus-4-8", candidates: [{ id: 0, finding: genericFinding() }] }),
    ).rejects.toSatisfy((err: Error) => {
      expect(err.message).not.toContain(API_KEY);
      return true;
    });
  });
});

describe("toSafeTriageError", () => {
  it("maps AuthenticationError to a clear, secret-free message", () => {
    const err = new Anthropic.AuthenticationError(401, {}, `bad creds ${API_KEY}`, new Headers());
    const safe = toSafeTriageError(err);
    expect(safe.message).not.toContain(API_KEY);
    expect(safe.message).toMatch(/authentication failed/i);
  });

  it("falls back to a generic message for a non-Anthropic error", () => {
    const safe = toSafeTriageError(new Error(`some unrelated crash near ${API_KEY}`));
    expect(safe.message).not.toContain(API_KEY);
  });
});
