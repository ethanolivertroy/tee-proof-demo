import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { nodePolyfills } from 'vite-plugin-node-polyfills'

export default defineConfig({
  plugins: [
    react(),
    nodePolyfills({
      include: ['buffer', 'crypto', 'stream', 'util', 'process', 'vm'],
      globals: { Buffer: true, global: true, process: true },
    }),
  ],
  define: {
    global: 'globalThis',
    process: '({ env: {}, browser: true, nextTick: queueMicrotask })',
  },
  build: { sourcemap: false },
})
