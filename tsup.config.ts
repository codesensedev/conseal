import { defineConfig } from 'tsup'

export default defineConfig({
  entry: ['src/index.ts'],
  format: ['esm'],
  outDir: 'dist',
  dts: {
    compilerOptions: {
      // tsup's DTS build via rollup-plugin-dts always injects baseUrl: ".",
      // which TypeScript 6.0 flags as deprecated. This silences that deprecation
      // only for DTS generation — the main tsconfig.json remains unmodified.
      ignoreDeprecations: '6.0',
    },
  },
})
