import { create } from "zustand";
import { persist } from "zustand/middleware";
export type SavedView = {
  name: string;
  userId?: string;
  page: string;
  q: string;
  severity?: string;
  status?: string;
  extra?: import("./QueryControls").ExtraFilters;
  number?: number;
  pageSize?: number;
  density?: "small"|"middle"|"large";
  hidden?: string[];
};
export const useViews = create<{
  views: SavedView[];
  save: (v: SavedView) => void;
  remove: (name: string) => void;
}>()(
  persist(
    (set) => ({
      views: [],
      save: (v) =>
        set((s) => ({
          views: [...s.views.filter((x) => x.name !== v.name || x.userId !== v.userId), v],
        })),
      remove: (name) =>
        set((s) => ({ views: s.views.filter((x) => x.name !== name) })),
    }),
    { name: "sg-saved-views" },
  ),
);
