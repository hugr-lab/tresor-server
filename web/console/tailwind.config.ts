import type { Config } from 'tailwindcss'

// Colours are the Hugr Lab design system's tokens, as CSS variables (src/styles.css): light on :root, dark on
// [data-theme="dark"]. Status colours are the console's own, in the same calm key.
export default {
  darkMode: ['selector', '[data-theme="dark"]'],
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        surface: 'var(--surface)',
        soft: 'var(--surface-soft)',
        ink: 'var(--ink)',
        muted: 'var(--ink-muted)',
        line: 'var(--border)',
        brand: 'var(--brand)',
        strong: 'var(--brand-strong)',
        'on-brand': 'var(--on-brand)',
        navy: 'var(--navy)',
        success: 'var(--success)',
        'success-soft': 'var(--success-soft)',
        warning: 'var(--warning)',
        'warning-soft': 'var(--warning-soft)',
        danger: 'var(--danger)',
        'danger-soft': 'var(--danger-soft)',
        row: 'var(--row)',
      },
      fontFamily: {
        sans: ['Manrope', 'system-ui', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'ui-monospace', 'monospace'],
      },
      borderRadius: { sm: '8px', md: '16px', lg: '28px' },
    },
  },
} satisfies Config
