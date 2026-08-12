import { describe, expect, it, vi } from "vitest";
import { fetchTextFile, type RepoContentClient } from "./repo-content";

function clientReturning(data: unknown): RepoContentClient {
  return { getContent: vi.fn().mockResolvedValue({ data }) };
}

describe("fetchTextFile", () => {
  it("decodes base64 file content", async () => {
    const content = Buffer.from("AKIAIOSFODNN7EXAMPLE\n").toString("base64");
    const client = clientReturning({ type: "file", content, encoding: "base64" });

    const text = await fetchTextFile(client, { owner: "acme", repo: "widgets", path: ".secretscanignore", ref: "sha" });
    expect(text).toBe("AKIAIOSFODNN7EXAMPLE\n");
  });

  it("returns undefined when the file does not exist (404)", async () => {
    const client: RepoContentClient = {
      getContent: vi.fn().mockRejectedValue(Object.assign(new Error("Not Found"), { status: 404 })),
    };

    const text = await fetchTextFile(client, { owner: "acme", repo: "widgets", path: ".secretscanignore", ref: "sha" });
    expect(text).toBeUndefined();
  });

  it("rethrows non-404 errors", async () => {
    const client: RepoContentClient = {
      getContent: vi.fn().mockRejectedValue(Object.assign(new Error("Forbidden"), { status: 403 })),
    };

    await expect(
      fetchTextFile(client, { owner: "acme", repo: "widgets", path: ".secretscanignore", ref: "sha" }),
    ).rejects.toThrow("Forbidden");
  });

  it("returns undefined when the path is a directory, not a file", async () => {
    const client = clientReturning([{ name: "a.ts" }, { name: "b.ts" }]);
    const text = await fetchTextFile(client, { owner: "acme", repo: "widgets", path: "src", ref: "sha" });
    expect(text).toBeUndefined();
  });

  it("returns undefined when the response has no content field", async () => {
    const client = clientReturning({ type: "submodule" });
    const text = await fetchTextFile(client, { owner: "acme", repo: "widgets", path: "vendor/lib", ref: "sha" });
    expect(text).toBeUndefined();
  });
});
