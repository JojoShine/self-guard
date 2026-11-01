import { beforeEach, describe, expect, it, vi } from "vitest";
vi.stubGlobal("sessionStorage", {
  getItem: () => null,
  setItem: vi.fn(),
  removeItem: vi.fn(),
});
const { api, useSession, parseObject } = await import("./api");
describe("authenticated API boundary", () => {
  beforeEach(() => {
    useSession.getState().setToken("session-test");
    vi.stubGlobal("fetch", vi.fn());
  });
  it("sends bearer authentication and preserves JSON payload", async () => {
    vi.mocked(fetch).mockResolvedValue(new Response('{"id":"one"}'));
    await api("/tasks", { title: "受控变更" });
    expect(fetch).toHaveBeenCalledWith(
      (import.meta.env.BASE_URL||"/")+"api/tasks",
      expect.objectContaining({
        method: "POST",
        headers: expect.objectContaining({
          Authorization: "Bearer session-test",
        }),
        body: '{"title":"受控变更"}',
      }),
    );
  });
  it("clears expired login and surfaces the server error", async () => {
    vi.mocked(fetch).mockResolvedValue(
      new Response('{"message":"登录已过期"}', { status: 401 }),
    );
    await expect(api("/assets")).rejects.toThrow("登录已过期");
    expect(useSession.getState().token).toBe("");
  });
  it("does not turn forbidden results into empty data", async () => {
    vi.mocked(fetch).mockResolvedValue(
      new Response('{"message":"无权限"}', { status: 403 }),
    );
    await expect(api("/users")).rejects.toThrow("无权限");
    expect(useSession.getState().token).toBe("session-test");
  });
  it("rejects arrays and null for configuration objects", () => {
    expect(() => parseObject("[]")).toThrow();
    expect(() => parseObject("null")).toThrow();
    expect(parseObject('{"enabled":true}')).toEqual({ enabled: true });
  });
});
