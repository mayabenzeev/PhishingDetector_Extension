import { defineConfig } from 'vite';
import { resolve } from 'path';
import { viteStaticCopy } from 'vite-plugin-static-copy';

export default defineConfig({
  plugins: [
    viteStaticCopy({
      targets: [
        { src: 'manifest.json', dest: '.' },
        { src: 'popup.html', dest: '.' },
        { src: 'rf_model.onnx', dest: '.' }
      ]
    })
  ],
  build: {
    emptyOutDir: true,
    outDir: 'dist',
    rollupOptions: {
      input: {
        background: resolve(__dirname, 'background.js'),
        popup: resolve(__dirname, 'popup.js'),
        content: resolve(__dirname, 'content-script.js')
      },
      output: {
        entryFileNames: '[name].js'
      }
    }
  }
});
