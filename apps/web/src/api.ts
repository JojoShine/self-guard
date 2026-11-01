import {apiURL} from './urls';
import { create } from "zustand";
export const useSession = create<{
  token: string;
  setToken: (token: string) => void;
}>((set) => ({
  token: sessionStorage.getItem("sg-token") || "",
  setToken: (token) => {
    token
      ? sessionStorage.setItem("sg-token", token)
      : sessionStorage.removeItem("sg-token");
    set({ token });
  },
}));
export async function api(
  path: string,
  body?: unknown,
  method = body ? "POST" : "GET",
) {
  const response = await fetch(apiURL(path), {
    method,
    headers: {
      "Content-Type": "application/json",
      ...(useSession.getState().token
        ? { Authorization: `Bearer ${useSession.getState().token}` }
        : {}),
    },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  const data = await response
    .json()
    .catch(() => ({ message: "服务器返回了无法读取的响应" }));
  if (!response.ok) {
    if (response.status === 401) useSession.getState().setToken("");
    throw new Error(
      Array.isArray(data.message)
        ? data.message.join("；")
        : data.message || "请求失败",
    );
  }
  return data;
}
export function parseObject(value: string) {
  const result = JSON.parse(value);
  if (!result || Array.isArray(result) || typeof result !== "object")
    throw new Error("请输入 JSON 对象");
  return result;
}
