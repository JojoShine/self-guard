import { describe, it, expect, vi } from "vitest";
vi.stubGlobal("localStorage", {
  getItem: () => null,
  setItem: vi.fn(),
  removeItem: vi.fn(),
});
vi.stubGlobal("window", { localStorage });
const { useViews } = await import("./views");
describe("saved filters", () => {
  it("keeps same-name views separate for different users",()=>{
    useViews.getState().save({name:"个人筛选",userId:"one",page:"risks",q:"private-one",pageSize:50,extra:{sortBy:"title",order:"asc",business:"A"}});
    useViews.getState().save({name:"个人筛选",userId:"two",page:"risks",q:"private-two"});
    expect(useViews.getState().views.filter(v=>v.name==="个人筛选")).toHaveLength(2);
    expect(useViews.getState().views.find(v=>v.userId==="one")?.extra?.business).toBe("A");
    expect(useViews.getState().views.find(v=>v.userId==="one")?.pageSize).toBe(50);
    useViews.getState().remove("个人筛选");
  });
  it("replaces a named saved view and preserves route-specific filters", () => {
    useViews
      .getState()
      .save({ name: "待处理", page: "risks", q: "linux", severity: "HIGH" });
    useViews
      .getState()
      .save({ name: "待处理", page: "alerts", q: "web", status: "OPEN" });
    expect(useViews.getState().views).toEqual([
      { name: "待处理", page: "alerts", q: "web", status: "OPEN" },
    ]);
    expect(localStorage.setItem).toHaveBeenCalled();
    useViews.getState().remove("待处理");
    expect(useViews.getState().views).toEqual([]);
  });
});
