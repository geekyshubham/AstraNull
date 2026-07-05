import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

const apiTarget = process.env.ASTRANULL_VITE_API_TARGET ?? 'http://127.0.0.1:3000';

export default defineConfig({
  root: 'apps/web/react',
  plugins: [react()],
  define: {
    'process.env.NODE_ENV': JSON.stringify('production')
  },
  server: {
    port: 5173,
    strictPort: false,
    proxy: {
      '/v1': apiTarget,
      '/ready': apiTarget,
      '/internal': apiTarget
    }
  },
  preview: {
    port: 4173,
    strictPort: false
  },
  build: {
    outDir: '../',
    emptyOutDir: false,
    cssCodeSplit: false,
    lib: {
      entry: 'src/main.tsx',
      formats: ['es'],
      fileName: () => 'react-app.js'
    },
    rollupOptions: {
      output: {
        assetFileNames: (assetInfo) => {
          if (assetInfo.name?.endsWith('.css')) return 'react-app.css';
          return 'react-[name][extname]';
        }
      }
    }
  }
});
