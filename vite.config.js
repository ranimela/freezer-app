import { defineConfig } from "vite";

export default defineConfig({
  server: {
    host: true, // Exposes the server to your local network (for mobile access)
    open: "/freezer.html",
  },
});
