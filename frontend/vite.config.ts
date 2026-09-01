import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: 5174,
    strictPort: true, // fail loudly if 5174 is taken, instead of drifting to 5175+
    proxy: {
      // Forward API calls to the Express backend during development.
      // Override with BACKEND_PORT=xxxx if 3000 is blocked — Windows
      // reserves dynamic port ranges (Hyper-V/WSL) that sometimes cover it.
      '/api': `http://127.0.0.1:${process.env.BACKEND_PORT || 3000}`,
    },
  },
})
