import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

const api = process.env.THREATLENS_API || 'http://127.0.0.1:8000';

export default defineConfig({
  plugins: [react()],
  server: { proxy: { '/api': api } },
  preview: { proxy: { '/api': api } },
  test: { environment: 'jsdom', setupFiles: ['./tests/setup.js'], globals: true },
});
