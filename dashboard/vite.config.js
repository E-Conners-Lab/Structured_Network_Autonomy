import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/evaluate': 'http://localhost:8000',
      '/escalation': 'http://localhost:8000',
      '/audit': 'http://localhost:8000',
      '/agents': 'http://localhost:8000',
      '/eas': 'http://localhost:8000',
      '/reports': 'http://localhost:8000',
      '/policy': 'http://localhost:8000',
      '/health': 'http://localhost:8000',
    },
  },
  build: {
    outDir: 'dist',
  },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: './src/setupTests.js',
  },
})
