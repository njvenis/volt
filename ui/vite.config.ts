import { defineConfig } from 'vite';
// Local same-origin read API. No credentials are built into the bundle.
export default defineConfig({ esbuild: { jsx: 'automatic' }, server: { host: '127.0.0.1' } });
