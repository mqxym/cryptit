import { expect, it } from 'bun:test';
import { execa } from 'execa';
import { fileURLToPath } from 'node:url';
import { CLI_PRELOAD } from './setup.js';

it('preserves all compatibility vectors with real Argon2', async () => {
  const result = await execa(process.execPath, [
    ...CLI_PRELOAD,
    'test',
    fileURLToPath(new URL('./cryptit.compatibility.vectors.ts', import.meta.url)),
  ], {
    env: { CRYPTIT_TEST_REAL_ARGON2: '1' },
    encoding: 'utf8',
  });
  expect(result.exitCode).toBe(0);
}, 30_000);
