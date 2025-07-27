import { defineConfig } from 'vitest/config';
export default defineConfig({
  test: {
    globals: true,
    coverage: { all: true, lines: 90 },
    environment: 'node'
  }
});