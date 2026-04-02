import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    environment: 'happy-dom',
    setupFiles: ['./test/setup.ts'],
    hookTimeout: 60000,
    testTimeout: 30000,
  },
})
