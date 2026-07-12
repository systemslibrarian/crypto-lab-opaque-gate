/// <reference types="vitest/config" />
import { defineConfig } from 'vite';

export default defineConfig({
  base: '/crypto-lab-opaque-gate/',
  build: {
    target: 'esnext',
    minify: 'esbuild',
    outDir: 'dist'
  },
  test: {
    // Unit/KAT suite only. The Playwright a11y e2e lives in e2e/ and is
    // driven by `npm run test:a11y`, never collected by vitest.
    include: ['tests/**/*.test.ts'],
    exclude: ['e2e/**', 'node_modules/**', 'dist/**']
  }
});
