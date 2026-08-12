import { describe, expect, it, vi } from "vitest";
import { MARKER, findExistingComment, upsertComment, type CommentsClient } from "./comment";

function fakeClient(existingComments: Array<{ id: number; body?: string | null }> = []): CommentsClient & {
  listComments: ReturnType<typeof vi.fn>;
  updateComment: ReturnType<typeof vi.fn>;
  createComment: ReturnType<typeof vi.fn>;
} {
  return {
    listComments: vi.fn().mockResolvedValue({ data: existingComments }),
    updateComment: vi.fn().mockResolvedValue({}),
    createComment: vi.fn().mockResolvedValue({ data: { id: 999 } }),
  };
}

describe("findExistingComment", () => {
  it("finds the comment carrying the hidden marker among unrelated comments", async () => {
    const client = fakeClient([
      { id: 1, body: "just a normal human comment" },
      { id: 2, body: `${MARKER}\nold summary` },
      { id: 3, body: "another comment" },
    ]);

    const found = await findExistingComment(client, "acme", "widgets", 42);
    expect(found?.id).toBe(2);
  });

  it("returns undefined when no comment carries the marker", async () => {
    const client = fakeClient([{ id: 1, body: "unrelated" }]);
    const found = await findExistingComment(client, "acme", "widgets", 42);
    expect(found).toBeUndefined();
  });

  it("treats a null body as no match rather than throwing", async () => {
    const client = fakeClient([{ id: 1, body: null }]);
    const found = await findExistingComment(client, "acme", "widgets", 42);
    expect(found).toBeUndefined();
  });
});

describe("upsertComment", () => {
  it("creates a new comment when none exists yet", async () => {
    const client = fakeClient([]);
    const id = await upsertComment(client, { owner: "acme", repo: "widgets", issueNumber: 7, body: "hello" });

    expect(client.createComment).toHaveBeenCalledTimes(1);
    expect(client.updateComment).not.toHaveBeenCalled();
    expect(id).toBe(999);

    const [call] = client.createComment.mock.calls;
    expect(call[0].body).toContain(MARKER);
    expect(call[0].body).toContain("hello");
  });

  it("updates the existing marked comment instead of creating a new one", async () => {
    const client = fakeClient([{ id: 55, body: `${MARKER}\nstale summary` }]);
    const id = await upsertComment(client, { owner: "acme", repo: "widgets", issueNumber: 7, body: "fresh summary" });

    expect(client.updateComment).toHaveBeenCalledTimes(1);
    expect(client.createComment).not.toHaveBeenCalled();
    expect(id).toBe(55);

    const [call] = client.updateComment.mock.calls;
    expect(call[0].comment_id).toBe(55);
    expect(call[0].body).toContain("fresh summary");
  });

  it("does not double-insert the marker if the caller's body already includes it", async () => {
    const client = fakeClient([]);
    await upsertComment(client, {
      owner: "acme",
      repo: "widgets",
      issueNumber: 7,
      body: `${MARKER}\nalready marked`,
    });

    const [call] = client.createComment.mock.calls;
    const occurrences = call[0].body.split(MARKER).length - 1;
    expect(occurrences).toBe(1);
  });

  it("ignores comments from previous unrelated marked runs on other issues is not its concern (scoped by issue_number param)", async () => {
    const client = fakeClient([]);
    await upsertComment(client, { owner: "acme", repo: "widgets", issueNumber: 123, body: "x" });

    const [[params]] = client.listComments.mock.calls;
    expect(params.issue_number).toBe(123);
  });
});
