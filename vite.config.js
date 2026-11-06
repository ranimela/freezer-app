import { resolve } from "path";
import { defineConfig } from "vite";

export default defineConfig({
  build: {
    rollupOptions: {
      input: {
        main: resolve(__dirname, "index.html"),
        freezer: resolve(__dirname, "freezer.html"),
      },
    },
  },
  server: {
    host: true,
  },
});
