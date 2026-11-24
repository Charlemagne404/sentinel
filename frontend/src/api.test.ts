import { afterEach, describe, expect, it, vi } from "vitest";
import { request, setCsrfToken, signIn } from "./api";

afterEach(() => {
  vi.restoreAllMocks();
  setCsrfToken(null);
});

describe("authenticated API client", () => {
  it("keeps session cookies same-origin and attaches the in-memory CSRF token", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify({ csrf_token: "csrf-1" }), { status: 200, headers: { "Content-Type": "application/json" } }));
    await signIn("admin", "password-that-is-not-stored");
    fetchMock.mockClear();
    fetchMock.mockResolvedValue(new Response(JSON.stringify({ saved: true }), { status: 200, headers: { "Content-Type": "application/json" } }));
    await request("/api/v1/config", { method: "PUT", body: "{}" });
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("/api/v1/config");
    expect(init?.credentials).toBe("same-origin");
    expect(new Headers(init?.headers).get("X-CSRF-Token")).toBe("csrf-1");
  });

  it("surfaces structured server errors with their HTTP status", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify({ error: "forbidden" }), { status: 403, headers: { "Content-Type": "application/json" } }));
    await expect(request("/api/v1/overview")).rejects.toMatchObject({ message: "forbidden", status: 403 });
  });
});
