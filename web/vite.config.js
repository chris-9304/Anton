import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// anton_api (src/api_server.rs) already sets CorsLayer::permissive(), so no dev
// proxy is needed here -- the app talks directly to http://localhost:8080.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
  },
});
