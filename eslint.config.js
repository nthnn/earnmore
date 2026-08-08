const tseslint = require('typescript-eslint');
const security = require('eslint-plugin-security');
const eslintPluginPrettierRecommended = require('eslint-plugin-prettier/recommended');

module.exports = tseslint.config(
  ...tseslint.configs.recommended,
  security.configs.recommended,
  eslintPluginPrettierRecommended,
  {
    rules: {
      '@typescript-eslint/no-explicit-any': 'off'
    }
  }
);
