import { defineConfig } from "vite";
export default defineConfig({
  base: (process.env.BASE_PATH || "") + "/",
  server: {
    proxy: {
      "/api": {
        target: process.env.API_PROXY_TARGET || "http://localhost:4000",
        changeOrigin: true,
      },
    },
  },
});
