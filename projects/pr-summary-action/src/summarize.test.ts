import { afterEach, describe, expect, it, vi } from "vitest";
import Anthropic from "@anthropic-ai/sdk";
import { summarizePr, toSafeSummarizeError } from "./summarize";

const SECRET = "sk-ant-super-secret-test-key-do-not-leak";

const baseParams = {
  apiKey: SECRET,
  model: "claude-opus-4-8",
  prTitle: "Add widget support",
  prBody: "Adds the widget module.",
  diffText: "=== src/widget.ts (added) ===\n+export const widget = 1;",
  diffTruncated: false,
};

describe("summarizePr", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("returns the text block from a successful Anthropic response (network mocked)", async () => {
    vi.spyOn(Anthropic.Messages.prototype, "create").mockResolvedValue({
      content: [{ type: "text", text: "## What changed\n- Added widget module" }],
    } as Anthropic.Message);

    const result = await summarizePr(baseParams);

    expect(result).toBe("## What changed\n- Added widget module");
  });

  it("passes the model, diff, and PR context to the API call", async () => {
    const spy = vi
      .spyOn(Anthropic.Messages.prototype, "create")
      .mockResolvedValue({ content: [{ type: "text", text: "summary" }] } as Anthropic.Message);

    await summarizePr(baseParams);

    expect(spy).toHaveBeenCalledTimes(1);
    const [request] = spy.mock.calls[0];
    expect(request.model).toBe("claude-opus-4-8");
    const userMessage = request.messages[0].content as string;
    expect(userMessage).toContain("Add widget support");
    expect(userMessage).toContain("export const widget = 1");
  });

  it("notes truncation to the model when the diff was cut", async () => {
    const spy = vi
      .spyOn(Anthropic.Messages.prototype, "create")
      .mockResolvedValue({ content: [{ type: "text", text: "summary" }] } as Anthropic.Message);

    await summarizePr({ ...baseParams, diffTruncated: true });

    const [request] = spy.mock.calls[0];
    const userMessage = request.messages[0].content as string;
    expect(userMessage.toLowerCase()).toContain("truncated");
  });

  it("throws instead of returning an empty summary", async () => {
    vi.spyOn(Anthropic.Messages.prototype, "create").mockResolvedValue({
      content: [{ type: "text", text: "   " }],
    } as Anthropic.Message);

    await expect(summarizePr(baseParams)).rejects.toThrow(/empty/i);
  });

  it("never leaks the API key even if the underlying SDK error happens to contain it", async () => {
    vi.spyOn(Anthropic.Messages.prototype, "create").mockRejectedValue(
      new Anthropic.AuthenticationError(
        401,
        { error: { message: `invalid key ${SECRET}` } },
        `invalid key ${SECRET}`,
        new Headers(),
      ),
    );

    await expect(summarizePr(baseParams)).rejects.toSatisfy((err: Error) => {
      expect(err.message).not.toContain(SECRET);
      return true;
    });
  });
});

describe("toSafeSummarizeError", () => {
  it("maps AuthenticationError to a clear, secret-free message", () => {
    const err = new Anthropic.AuthenticationError(401, {}, `bad creds ${SECRET}`, new Headers());
    const safe = toSafeSummarizeError(err);
    expect(safe.message).not.toContain(SECRET);
    expect(safe.message).toMatch(/authentication failed/i);
  });

  it("maps RateLimitError to a clear, secret-free message", () => {
    const err = new Anthropic.RateLimitError(429, {}, `rate limited ${SECRET}`, new Headers());
    const safe = toSafeSummarizeError(err);
    expect(safe.message).not.toContain(SECRET);
    expect(safe.message).toMatch(/rate limit/i);
  });

  it("maps a generic APIError to a status-only message without echoing the raw body", () => {
    const err = new Anthropic.APIError(500, { error: { message: `server saw ${SECRET}` } }, "boom", new Headers());
    const safe = toSafeSummarizeError(err);
    expect(safe.message).not.toContain(SECRET);
    expect(safe.message).toContain("500");
  });

  it("maps APIConnectionError to a transient-network message", () => {
    const err = new Anthropic.APIConnectionError({ message: `dns failure near ${SECRET}` });
    const safe = toSafeSummarizeError(err);
    expect(safe.message).not.toContain(SECRET);
    expect(safe.message).toMatch(/connect/i);
  });

  it("falls back to a generic message for a non-Anthropic error", () => {
    const safe = toSafeSummarizeError(new Error(`some unrelated crash near ${SECRET}`));
    expect(safe.message).not.toContain(SECRET);
  });

  it("falls back to a generic message for a thrown non-Error value", () => {
    const safe = toSafeSummarizeError(SECRET);
    expect(safe.message).not.toContain(SECRET);
  });
});
