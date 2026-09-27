import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// Served from /ui/ by the Rust admin server. Same-origin fetches.
export default defineConfig({
  base: '/ui/',
  plugins: [react(), tailwindcss()],
  server: {
    port: 5173,
  },
})
