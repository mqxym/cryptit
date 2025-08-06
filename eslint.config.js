// eslint.config.js
import tsParser from '@typescript-eslint/parser';
import tsPlugin from '@typescript-eslint/eslint-plugin';
import { FlatCompat } from '@eslint/eslintrc';
 
const compat = new FlatCompat({
  baseDirectory: import.meta.url,
});

export default [
  {
    ignores: ['**/dist/**'],
  },
  ...compat.extends('plugin:@typescript-eslint/recommended'),

  {
    ignores: ['**/__tests__/**'],
  },
  {
    ignores: ['**/build/**'],
  },
  {
    files: ['*/packages/*/*.ts'],
    languageOptions: {
      parser: tsParser,
      parserOptions: { project: './tsconfig.json' },
    },
    plugins: {
      '@typescript-eslint': tsPlugin,
    },
    rules: {
      '@typescript-eslint/explicit-function-return-type': 'warn',
    },
  },
];