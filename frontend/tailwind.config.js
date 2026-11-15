/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        cyber: {
          dark: '#070C18',
          sidebar: '#0B132B',
          card: '#131E3D',
          hover: '#19284F',
          accent: '#1E50FF',
          cyan: '#00C2FF',
          border: '#1E2C52',
        },
        forensic: {
          canvas: '#F4F7FC',
          card: '#FFFFFF',
          border: '#E2E8F0',
          textDark: '#0F172A',
          textMuted: '#64748B',
          observed: '#10B981',
          correlated: '#3B82F6',
          reconstructed: '#8B5CF6',
          suspicious: '#EF4444',
          unknown: '#94A3B8',
        }
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'Segoe UI', 'Roboto', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'Consolas', 'monospace'],
      }
    },
  },
  plugins: [],
}

