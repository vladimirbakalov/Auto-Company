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

const octokitMock = {
  paginate,
  rest: {
    issues: { listComments, updateComment, createComment },
    pulls: { listFiles },
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
    "anthropic-api-key": "sk-ant-test-key",
    "github-token": "gh-token",
    model: "claude-opus-4-8",
    "max-diff-chars": "60000",
  };
  return { ...defaults, ...overrides };
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

  it("posts a helpful, non-failing comment when the API key is missing", async () => {
    contextPayload = { pull_request: { number: 7, title: "t", body: "b" } };
    coreMock.getInput.mockImplementation((key: string) => inputs({ "anthropic-api-key": "" })[key] ?? "");
    paginate.mockResolvedValue([]); // listComments -> none existing
    createComment.mockResolvedValue({ data: { id: 1 } });

    const { run } = await import("./run");
    await run();

    expect(coreMock.warning).toHaveBeenCalled();
    expect(messagesCreate).not.toHaveBeenCalled();
    expect(createComment).toHaveBeenCalledTimes(1);
    expect(createComment.mock.calls[0][0].body).toContain("no Anthropic API key configured");
    expect(coreMock.setFailed).not.toHaveBeenCalled();
  });

  it("generates a summary and creates a comment on first run", async () => {
    contextPayload = { pull_request: { number: 7, title: "Add feature", body: "desc" } };
    coreMock.getInput.mockImplementation((key: string) => inputs()[key] ?? "");

    listFiles.mockName("listFiles");
    paginate.mockImplementation(async (fn: unknown) => {
      if (fn === listFiles) {
        return [
          {
            filename: "src/a.ts",
            status: "modified",
            additions: 1,
            deletions: 0,
            changes: 1,
            patch: "+console.log(1)",
          },
        ];
      }
      return []; // listComments
    });
    createComment.mockResolvedValue({ data: { id: 42 } });
    messagesCreate.mockResolvedValue({ content: [{ type: "text", text: "## What changed\n- Added a.ts" }] });

    const { run } = await import("./run");
    await run();

    expect(messagesCreate).toHaveBeenCalledTimes(1);
    expect(createComment).toHaveBeenCalledTimes(1);
    expect(updateComment).not.toHaveBeenCalled();
    expect(coreMock.setOutput).toHaveBeenCalledWith("summary", "## What changed\n- Added a.ts");
    expect(coreMock.setOutput).toHaveBeenCalledWith("comment-id", "42");
    expect(coreMock.setFailed).not.toHaveBeenCalled();
  });

  it("updates the existing marked comment on a subsequent push instead of creating a new one", async () => {
    contextPayload = { pull_request: { number: 7, title: "Add feature", body: "desc" } };
    coreMock.getInput.mockImplementation((key: string) => inputs()[key] ?? "");

    paginate.mockImplementation(async (fn: unknown) => {
      if (fn === listFiles) {
        return [{ filename: "src/a.ts", status: "modified", additions: 1, deletions: 0, changes: 1, patch: "+x" }];
      }
      return [{ id: 555, body: "<!-- pr-summary-action:comment -->\nold summary" }];
    });
    messagesCreate.mockResolvedValue({ content: [{ type: "text", text: "new summary" }] });

    const { run } = await import("./run");
    await run();

    expect(updateComment).toHaveBeenCalledTimes(1);
    expect(createComment).not.toHaveBeenCalled();
    expect(updateComment.mock.calls[0][0].comment_id).toBe(555);
  });

  it("fails the step with a sanitized message when the Anthropic call errors, without posting a comment", async () => {
    contextPayload = { pull_request: { number: 7, title: "t", body: "b" } };
    coreMock.getInput.mockImplementation((key: string) => inputs()[key] ?? "");

    paginate.mockImplementation(async (fn: unknown) => {
      if (fn === listFiles) {
        return [{ filename: "src/a.ts", status: "modified", additions: 1, deletions: 0, changes: 1, patch: "+x" }];
      }
      return [];
    });
    messagesCreate.mockRejectedValue(new Error("network exploded"));

    const { run } = await import("./run");
    await run();

    expect(coreMock.setFailed).toHaveBeenCalledTimes(1);
    expect(createComment).not.toHaveBeenCalled();
    expect(updateComment).not.toHaveBeenCalled();
  });

  it("does nothing when the pull_request event has no payload", async () => {
    contextPayload = {};
    coreMock.getInput.mockImplementation((key: string) => inputs()[key] ?? "");

    const { run } = await import("./run");
    await run();

    expect(listFiles).not.toHaveBeenCalled();
    expect(coreMock.setFailed).not.toHaveBeenCalled();
  });
});
