export default [
  {
    files: ['**/*.js', '**/*.mjs'],
    languageOptions: {
      ecmaVersion: 2024,
      sourceType: 'module',
      globals: {
        console: 'readonly',
        process: 'readonly',
        performance: 'readonly',
        URL: 'readonly',
      },
    },
    rules: {
      'no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
      'no-eval': 'error',
      'no-implied-eval': 'error',
      'no-new-func': 'error',
      'prefer-const': 'error',
      eqeqeq: 'error',
      'no-var': 'error',
    },
  },
  {
    // Allow eval references in test fixtures and rule definitions
    // (we're pattern-matching for it, not executing it).
    files: ['tests/fixtures/**', 'src/rules/**'],
    rules: {
      'no-eval': 'off',
      'no-implied-eval': 'off',
      'no-new-func': 'off',
      'no-unused-vars': 'off',
    },
  },
];
