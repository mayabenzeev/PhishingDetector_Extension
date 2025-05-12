import { defineConfig } from 'vite';

export default defineConfig({
  build: {
    rollupOptions: {
      input: {
        popup: 'popup.js',
        background: 'background.js',
        content: 'content-script.js'
      },
      output: {
        entryFileNames: '[name].js'
      }
    },
    outDir: 'dist'
  }
});
