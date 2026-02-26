import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5174,
    proxy: {
      '/evaluate': 'http://localhost:8001',
      '/escalation': 'http://localhost:8001',
      '/audit': 'http://localhost:8001',
      '/agents': 'http://localhost:8001',
      '/eas': 'http://localhost:8001',
      '/reports': 'http://localhost:8001',
      '/policy': 'http://localhost:8001',
      '/health': 'http://localhost:8001',
      '/devices': 'http://localhost:8001',
      '/timeline': 'http://localhost:8001',
    },
  },
  base: '/dashboard/',
  build: {
    outDir: 'dist',
  },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: './src/setupTests.js',
  },
})
