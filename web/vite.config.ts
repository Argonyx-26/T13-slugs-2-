import path from "path"
import tailwindcss from "@tailwindcss/vite"
import react from "@vitejs/plugin-react"
import { defineConfig } from "vite"

// The control plane (FastAPI, port 7000) serves the built UI, so the build goes straight
// into its static folder. `npm run dev` proxies API calls and the live event stream to it.
const CONTROL = process.env.MIRAGE_CONTROL_URL ?? "http://127.0.0.1:7000"

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      "@": path.resolve(import.meta.dirname, "./src"),
    },
  },
  build: {
    outDir: path.resolve(import.meta.dirname, "../mirage/static/app"),
    emptyOutDir: true,
  },
  server: {
    proxy: {
      "/api": CONTROL,
      "/events": CONTROL,
      "/classic": CONTROL,
    },
  },
})
