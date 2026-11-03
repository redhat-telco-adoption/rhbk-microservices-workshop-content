import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('.', import.meta.url));

export default defineConfig({
  plugins: [react()],
  build: {
    rollupOptions: {
      input: {
        main: resolve(root, 'index.html'),
        popupCallback: resolve(root, 'auth/popup-callback/index.html'),
        logoutCallback: resolve(root, 'auth/logout-callback/index.html'),
      },
    },
  },
});
