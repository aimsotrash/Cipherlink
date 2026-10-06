// typescript-eslint's recommended rules for every source file; its parser also
// reads the plain .js/.mjs scripts.
import tseslint from '@typescript-eslint/eslint-plugin';

export default [
  { ignores: ['**/dist/'] },
  ...tseslint.configs['flat/recommended'],
  {
    rules: {
      // `let x;` before a closure that reads it, assigned once later, is how
      // this code wires a callback to an object created after it.
      'prefer-const': ['error', { ignoreReadBeforeAssign: true }],
    },
  },
];
