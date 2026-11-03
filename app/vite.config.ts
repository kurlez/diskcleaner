import { defineConfig } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';

// Tauri 开发服务器要求固定端口。
export default defineConfig({
  plugins: [svelte()],
  base: './',
  clearScreen: false,
  server: { port: 1420, strictPort: true },
  build: { target: 'es2022', sourcemap: false },
  test: { include: ['src/**/*.test.ts'] },
});
