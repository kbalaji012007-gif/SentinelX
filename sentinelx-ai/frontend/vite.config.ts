import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import path from "path";

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      "@": path.resolve(import.meta.dirname, "./src"),
      "@components": path.resolve(import.meta.dirname, "./src/components"),
      "@features": path.resolve(import.meta.dirname, "./src/features"),
      "@hooks": path.resolve(import.meta.dirname, "./src/hooks"),
      "@services": path.resolve(import.meta.dirname, "./src/services"),
      "@stores": path.resolve(import.meta.dirname, "./src/stores"),
      "@types": path.resolve(import.meta.dirname, "./src/types"),
      "@utils": path.resolve(import.meta.dirname, "./src/utils"),
      "@styles": path.resolve(import.meta.dirname, "./src/styles"),
      "@assets": path.resolve(import.meta.dirname, "./src/assets"),
    },
  },
  server: {
    port: 5173,
    host: true,
    proxy: {
      "/api": {
        target: process.env.VITE_API_URL || "https://sentinelx-2qer.onrender.com",
        changeOrigin: true,
      },
      "/ws": {
        target: (process.env.VITE_API_URL || "https://sentinelx-2qer.onrender.com").replace(/^http/, "ws"),
        ws: true,
      },
    },
  },
  build: {
    outDir: "dist",
    sourcemap: true,
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (id.includes("node_modules")) {
            if (id.includes("recharts")) return "charts";
            if (id.includes("react-router-dom")) return "vendor";
            return "vendor";
          }
        },
      },
    },
  },
});
