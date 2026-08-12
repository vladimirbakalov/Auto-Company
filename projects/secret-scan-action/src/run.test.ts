import { afterEach, describe, expect, it, vi } from "vitest";

const coreMock = {
  getInput: vi.fn(),
  info: vi.fn(),
  warning: vi.fn(),
  setFailed: vi.fn(),
  setOutput: vi.fn(),
};

const paginate = vi.fn();
const listComments = vi.fn();
const updateComment = vi.fn();
const createComment = vi.fn();
const listFiles = vi.fn();
const getContent = vi.fn();

const octokitMock = {
  paginate,
  rest: {
    issues: { listComments, updateComment, createComment },
    pulls: { listFiles },
    repos: { getContent },
  },
};

let contextPayload: Record<string, unknown> = {};
let eventName = "pull_request";

vi.mock("@actions/core", () => coreMock);
vi.mock("@actions/github", () => ({
  get context() {
    return {
      eventName,
      payload: contextPayload,
      repo: { owner: "acme", repo: "widgets" },
      sha: "fallback-sha",
    };
  },
  getOctokit: vi.fn(() => octokitMock),
}));

const messagesCreate = vi.fn();
vi.mock("@anthropic-ai/sdk", async () => {
  const actual = await vi.importActual<typeof import("@anthropic-ai/sdk")>("@anthropic-ai/sdk");
  class FakeAnthropic {
    messages = { create: messagesCreate };
  }
  return { ...actual, default: FakeAnthropic };
});

function inputs(overrides: Record<string, string> = {}) {
  const defaults: Record<string, string> = {
    "github-token": "gh-token",
    "anthropic-api-key": "",
    model: "claude-opus-4-8",
    allowlist: "",
    "allowlist-path": ".secretscanignore",
    "fail-on": "high",
  };
  return { ...defaults, ...overrides };
}

function notFound(): never {
  throw Object.assign(new Error("Not Found"), { status: 404 });
}

describe("run", () => {
  afterEach(() => {
    vi.clearAllMocks();
    contextPayload = {};
    eventName = "pull_request";
  });

  it("does nothing on a non-pull_request event", async () => {
    eventName = "push";
    coreMock.getInput.mockImplementation((key: string) => inputs()[key] ?? "");

    const { run } = await import("./run");
    await run();

    expect(listFiles).not.toHaveBeenCalled();
    expect(coreMock.setFailed).not.toHaveBeenCalled();
  });

  it("does nothing when the pull_request event has no payload", async () => {
    contextPayload = {};
    coreMock.getInput.mockImplementation((key: string) => inputs()[key] ?? "");

    const { run } = await import("./run");
    await run();

    expect(listFiles).not.toHaveBeenCalled();
    expect(coreMock.setFailed).not.toHaveBeenCalled();
  });

  it("does nothing when the PR has no changed files", async () => {
    contextPayload = { pull_request: { number: 7, head: { sha: "abc" }, base: { sha: "base-sha" } } };
    coreMock.getInput.mockImplementation((key: string) => inputs()[key] ?? "");
    paginate.mockImplementation(async (fn: unknown) => (fn === listFiles ? [] : []));

    const { run } = await import("./run");
    await run();

    expect(createComment).not.toHaveBeenCalled();
    expect(coreMock.setFailed).not.toHaveBeenCalled();
  });

  it("posts a clean-scan comment and does not fail when no secrets are found", async () => {
    contextPayload = { pull_request: { number: 7, head: { sha: "abc" }, base: { sha: "base-sha" } } };
    coreMock.getInput.mockImplementation((key: string) => inputs()[key] ?? "");
    getContent.mockImplementation(notFound);
    paginate.mockImplementation(async (fn: unknown) => {
      if (fn === listFiles) {
        return [
          {
            filename: "src/a.ts",
            status: "modified",
            additions: 1,
            deletions: 0,
            changes: 1,
            patch: "@@ -1,1 +1,1 @@\n+const clean = true;",
          },
        ];
      }
      return []; // listComments
    });
    createComment.mockResolvedValue({ data: { id: 1 } });

    const { run } = await import("./run");
    await run();

    expect(createComment).toHaveBeenCalledTimes(1);
    expect(createComment.mock.calls[0][0].body).toContain("No secrets detected");
    expect(coreMock.setFailed).not.toHaveBeenCalled();
    expect(coreMock.setOutput).toHaveBeenCalledWith("findings-count", "0");
    expect(coreMock.setOutput).toHaveBeenCalledWith("high-confidence-count", "0");
  });

  it("fails the check and posts findings when a high-confidence secret is added", async () => {
    contextPayload = { pull_request: { number: 7, head: { sha: "abc" }, base: { sha: "base-sha" } } };
    coreMock.getInput.mockImplementation((key: string) => inputs()[key] ?? "");
    getContent.mockImplementation(notFound);
    paginate.mockImplementation(async (fn: unknown) => {
      if (fn === listFiles) {
        return [
          {
            filename: "src/a.ts",
            status: "modified",
            additions: 1,
            deletions: 0,
            changes: 1,
            patch: '@@ -1,1 +1,1 @@\n+const key = "AKIAIOSFODNN7EXAMPLE";',
          },
        ];
      }
      return [];
    });
    createComment.mockResolvedValue({ data: { id: 2 } });

    const { run } = await import("./run");
    await run();

    expect(createComment).toHaveBeenCalledTimes(1);
    expect(createComment.mock.calls[0][0].body).toContain("AWS Access Key ID");
    expect(createComment.mock.calls[0][0].body).not.toContain("AKIAIOSFODNN7EXAMPLE");
    expect(coreMock.setFailed).toHaveBeenCalledTimes(1);
    expect(coreMock.setOutput).toHaveBeenCalledWith("high-confidence-count", "1");
  });

  it("updates the existing marked comment instead of creating a new one on a subsequent push", async () => {
    contextPayload = { pull_request: { number: 7, head: { sha: "abc" }, base: { sha: "base-sha" } } };
    coreMock.getInput.mockImplementation((key: string) => inputs()[key] ?? "");
    getContent.mockImplementation(notFound);
    paginate.mockImplementation(async (fn: unknown) => {
      if (fn === listFiles) {
        return [{ filename: "src/a.ts", status: "modified", additions: 1, deletions: 0, changes: 1, patch: "@@ -1,1 +1,1 @@\n+clean" }];
      }
      return [{ id: 555, body: "<!-- secret-scan-action:comment -->\nold" }];
    });

    const { run } = await import("./run");
    await run();

    expect(updateComment).toHaveBeenCalledTimes(1);
    expect(createComment).not.toHaveBeenCalled();
    expect(updateComment.mock.calls[0][0].comment_id).toBe(555);
  });

  it("does not fail the check on a generic-tier-only finding when fail-on is 'high' (default)", async () => {
    contextPayload = { pull_request: { number: 7, head: { sha: "abc" }, base: { sha: "base-sha" } } };
    coreMock.getInput.mockImplementation((key: string) => inputs()[key] ?? "");
    getContent.mockImplementation(notFound);
    paginate.mockImplementation(async (fn: unknown) => {
      if (fn === listFiles) {
        return [
          {
            filename: "src/a.ts",
            status: "modified",
            additions: 1,
            deletions: 0,
            changes: 1,
            patch: '@@ -1,1 +1,1 @@\n+const apiToken = "zT9pQ2xR7mK4vL8nW1sD6fH3jC0bA5eY";',
          },
        ];
      }
      return [];
    });
    createComment.mockResolvedValue({ data: { id: 3 } });

    const { run } = await import("./run");
    await run();

    expect(coreMock.setFailed).not.toHaveBeenCalled();
    expect(createComment.mock.calls[0][0].body).toContain("Needs review");
  });

  it("fails the check on a generic-tier finding when fail-on is 'any'", async () => {
    contextPayload = { pull_request: { number: 7, head: { sha: "abc" }, base: { sha: "base-sha" } } };
    coreMock.getInput.mockImplementation((key: string) => inputs({ "fail-on": "any" })[key] ?? "");
    getContent.mockImplementation(notFound);
    paginate.mockImplementation(async (fn: unknown) => {
      if (fn === listFiles) {
        return [
          {
            filename: "src/a.ts",
            status: "modified",
            additions: 1,
            deletions: 0,
            changes: 1,
            patch: '@@ -1,1 +1,1 @@\n+const apiToken = "zT9pQ2xR7mK4vL8nW1sD6fH3jC0bA5eY";',
          },
        ];
      }
      return [];
    });
    createComment.mockResolvedValue({ data: { id: 4 } });

    const { run } = await import("./run");
    await run();

    expect(coreMock.setFailed).toHaveBeenCalledTimes(1);
  });

  it("suppresses an allowlisted finding via the inline allowlist input", async () => {
    contextPayload = { pull_request: { number: 7, head: { sha: "abc" }, base: { sha: "base-sha" } } };
    coreMock.getInput.mockImplementation(
      (key: string) => inputs({ allowlist: "AKIAIOSFODNN7EXAMPLE" })[key] ?? "",
    );
    getContent.mockImplementation(notFound);
    paginate.mockImplementation(async (fn: unknown) => {
      if (fn === listFiles) {
        return [
          {
            filename: "src/a.ts",
            status: "modified",
            additions: 1,
            deletions: 0,
            changes: 1,
            patch: '@@ -1,1 +1,1 @@\n+const key = "AKIAIOSFODNN7EXAMPLE";',
          },
        ];
      }
      return [];
    });
    createComment.mockResolvedValue({ data: { id: 5 } });

    const { run } = await import("./run");
    await run();

    expect(coreMock.setFailed).not.toHaveBeenCalled();
    expect(createComment.mock.calls[0][0].body).toContain("No secrets detected");
  });

  it("suppresses an allowlisted finding via a .secretscanignore file read from the repo", async () => {
    contextPayload = { pull_request: { number: 7, head: { sha: "abc" }, base: { sha: "base-sha" } } };
    coreMock.getInput.mockImplementation((key: string) => inputs()[key] ?? "");
    getContent.mockResolvedValue({
      data: { type: "file", content: Buffer.from("AKIAIOSFODNN7EXAMPLE").toString("base64") },
    });
    paginate.mockImplementation(async (fn: unknown) => {
      if (fn === listFiles) {
        return [
          {
            filename: "src/a.ts",
            status: "modified",
            additions: 1,
            deletions: 0,
            changes: 1,
            patch: '@@ -1,1 +1,1 @@\n+const key = "AKIAIOSFODNN7EXAMPLE";',
          },
        ];
      }
      return [];
    });
    createComment.mockResolvedValue({ data: { id: 6 } });

    const { run } = await import("./run");
    await run();

    expect(getContent).toHaveBeenCalledWith(expect.objectContaining({ path: ".secretscanignore", ref: "base-sha" }));
    expect(coreMock.setFailed).not.toHaveBeenCalled();
  });

  it("reads the allowlist file from the PR's BASE commit, not its head — a PR must not be able to self-suppress a secret it just introduced", async () => {
    contextPayload = { pull_request: { number: 7, head: { sha: "attacker-head-sha" }, base: { sha: "trusted-base-sha" } } };
    coreMock.getInput.mockImplementation((key: string) => inputs()[key] ?? "");
    // Simulate: the allowlist entry that would suppress this secret only
    // exists on the PR's head (added by the same PR), not on base.
    getContent.mockImplementation(async (params: { ref: string }) => {
      if (params.ref === "trusted-base-sha") throw Object.assign(new Error("Not Found"), { status: 404 });
      return { data: { type: "file", content: Buffer.from("AKIAIOSFODNN7EXAMPLE").toString("base64") } };
    });
    paginate.mockImplementation(async (fn: unknown) => {
      if (fn === listFiles) {
        return [
          {
            filename: "src/a.ts",
            status: "modified",
            additions: 1,
            deletions: 0,
            changes: 1,
            patch: '@@ -1,1 +1,1 @@\n+const key = "AKIAIOSFODNN7EXAMPLE";',
          },
        ];
      }
      return [];
    });
    createComment.mockResolvedValue({ data: { id: 9 } });

    const { run } = await import("./run");
    await run();

    expect(getContent).toHaveBeenCalledWith(expect.objectContaining({ ref: "trusted-base-sha" }));
    expect(getContent).not.toHaveBeenCalledWith(expect.objectContaining({ ref: "attacker-head-sha" }));
    // The secret was NOT suppressed, because the allowlist entry only exists on head.
    expect(coreMock.setFailed).toHaveBeenCalledTimes(1);
    expect(createComment.mock.calls[0][0].body).toContain("AWS Access Key ID");
  });

  it("skips the allowlist file entirely (does not fall back to head) when the PR's base sha is unavailable", async () => {
    contextPayload = { pull_request: { number: 7, head: { sha: "abc" } } }; // no base
    coreMock.getInput.mockImplementation((key: string) => inputs()[key] ?? "");
    paginate.mockImplementation(async (fn: unknown) => {
      if (fn === listFiles) {
        return [{ filename: "src/a.ts", status: "modified", additions: 1, deletions: 0, changes: 1, patch: "@@ -1,1 +1,1 @@\n+clean" }];
      }
      return [];
    });
    createComment.mockResolvedValue({ data: { id: 10 } });

    const { run } = await import("./run");
    await run();

    expect(getContent).not.toHaveBeenCalled();
    expect(coreMock.warning).toHaveBeenCalledWith(expect.stringContaining("base commit"));
  });

  it("runs Claude triage on generic findings when an API key is provided, dropping model-identified false positives", async () => {
    contextPayload = { pull_request: { number: 7, head: { sha: "abc" }, base: { sha: "base-sha" } } };
    coreMock.getInput.mockImplementation(
      (key: string) => inputs({ "anthropic-api-key": "sk-ant-test" })[key] ?? "",
    );
    getContent.mockImplementation(notFound);
    paginate.mockImplementation(async (fn: unknown) => {
      if (fn === listFiles) {
        return [
          {
            filename: "src/a.ts",
            status: "modified",
            additions: 1,
            deletions: 0,
            changes: 1,
            patch: '@@ -1,1 +1,1 @@\n+const apiToken = "zT9pQ2xR7mK4vL8nW1sD6fH3jC0bA5eY";',
          },
        ];
      }
      return [];
    });
    createComment.mockResolvedValue({ data: { id: 7 } });
    messagesCreate.mockResolvedValue({ content: [{ type: "text", text: '[{"id": 0, "isLikelySecret": false}]' }] });

    const { run } = await import("./run");
    await run();

    expect(messagesCreate).toHaveBeenCalledTimes(1);
    expect(createComment.mock.calls[0][0].body).toContain("No secrets detected");
    expect(coreMock.setFailed).not.toHaveBeenCalled();
  });

  it("falls back to reporting all generic findings, unfiltered, if triage itself errors", async () => {
    contextPayload = { pull_request: { number: 7, head: { sha: "abc" }, base: { sha: "base-sha" } } };
    coreMock.getInput.mockImplementation(
      (key: string) => inputs({ "anthropic-api-key": "sk-ant-test" })[key] ?? "",
    );
    getContent.mockImplementation(notFound);
    paginate.mockImplementation(async (fn: unknown) => {
      if (fn === listFiles) {
        return [
          {
            filename: "src/a.ts",
            status: "modified",
            additions: 1,
            deletions: 0,
            changes: 1,
            patch: '@@ -1,1 +1,1 @@\n+const apiToken = "zT9pQ2xR7mK4vL8nW1sD6fH3jC0bA5eY";',
          },
        ];
      }
      return [];
    });
    createComment.mockResolvedValue({ data: { id: 8 } });
    messagesCreate.mockRejectedValue(new Error("network exploded"));

    const { run } = await import("./run");
    await run();

    expect(coreMock.warning).toHaveBeenCalled();
    expect(createComment.mock.calls[0][0].body).toContain("Needs review");
    expect(coreMock.setFailed).not.toHaveBeenCalled(); // still fail-on: high (default), generic tier alone doesn't fail
  });
});
