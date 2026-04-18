import { defineConfig } from 'vite';

export default defineConfig({
  base: '/crypto-lab-opaque-gate/',
  build: {
    target: 'esnext',
    minify: 'esbuild',
    outDir: 'dist'
  }
});
