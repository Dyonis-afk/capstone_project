// import { defineConfig } from 'vite'
// import react from '@vitejs/plugin-react'

// // https://vite.dev/config/
// export default defineConfig({
//   plugins: [react(), tailwindcss()],
// })

import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import electron from 'vite-plugin-electron';
import { resolve } from 'path';
import tailwindcss from '@tailwindcss/vite'

// List of Node.js built-in modules that should be externalized
const nodeBuiltins = [
  'fs',
  'path',
  'url',
  'child_process',
  'util',
  'os',
  'crypto',
  'stream',
  'events',
  'buffer',
  'process'
];

export default defineConfig({
  plugins: [
    react(),
    tailwindcss(),
    electron([
      {
        entry: 'electron/main.ts',
        vite: {
          build: {
            outDir: 'dist-electron',
            format: 'es',
            rollupOptions: {
              external: (id) => {
                // Externalize Node.js built-ins
                if (nodeBuiltins.includes(id)) return true;
                // Externalize Electron
                if (id === 'electron') return true;
                // Externalize native modules and electron packages
                if (id === 'better-sqlite3' || id === 'neo4j-driver' || id === 'adm-zip' || id === 'electron-updater') return true;
                // Externalize if it starts with 'node:' (Node.js built-ins with prefix)
                if (id.startsWith('node:')) return true;
                return false;
              }
            }
          }
        }
      },
      {
        entry: 'electron/preload.ts',
        vite: {
          build: {
            outDir: 'dist-electron',
            format: 'es',
            rollupOptions: {
              external: (id) => {
                if (id === 'electron') return true;
                if (nodeBuiltins.includes(id)) return true;
                if (id.startsWith('node:')) return true;
                return false;
              }
            }
          }
        }
      }
    ])
  ],
  resolve: {
    alias: {
      '@': resolve(__dirname, 'src'),
      '@electron': resolve(__dirname, 'electron')
    }
  }
});