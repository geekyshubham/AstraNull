import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

const apiTarget = process.env.ASTRANULL_VITE_API_TARGET ?? 'http://127.0.0.1:3000';

export default defineConfig({
  root: 'apps/web/react',
  plugins: [react(), {
    name: 'portal-source-entrypoints',
    configureServer(server) {
      // Staff documents share /internal with API routes, but must load the source entry.
      server.middlewares.use((req, _res, next) => {
        const pathname = req.url?.split('?')[0];
        if ((req.method === 'GET' || req.method === 'HEAD')
          && ['/internal/admin', '/internal/soc', '/internal/admin/login'].includes(pathname ?? '')) {
          req.url = '/index.html';
        }
        next();
      });
    }
  }],
  define: {
    'process.env.NODE_ENV': JSON.stringify('production')
  },
  resolve: {
    dedupe: ['react', 'react-dom']
  },
  // Admit the complete runtime graph before first delivery. Late optimizer discovery can
  // otherwise load two React instances under different versioned URLs on a cold start.
  optimizeDeps: {
    include: [
      'react', 'react-dom', 'react-dom/client', 'react/jsx-runtime', 'react/jsx-dev-runtime',
      'lucide-react', 'clsx', 'tailwind-merge', 'class-variance-authority'
    ]
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
    copyPublicDir: false,
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
