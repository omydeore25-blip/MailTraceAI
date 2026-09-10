/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        border: "hsl(var(--border, 214.3 31.8% 91.4%))",
        background: "hsl(var(--background, 222.2 84% 4.9%))",
        foreground: "hsl(var(--foreground, 210 40% 98%))",
        card: {
          DEFAULT: "hsl(var(--card, 222.2 84% 6.5%))",
          foreground: "hsl(var(--card-foreground, 210 40% 98%))",
        },
        primary: {
          DEFAULT: "hsl(var(--primary, 217.2 91.2% 59.8%))",
          foreground: "hsl(var(--primary-foreground, 222.2 47.4% 11.2%))",
        },
        muted: {
          DEFAULT: "hsl(var(--muted, 217.2 32.6% 17.5%))",
          foreground: "hsl(var(--muted-foreground, 215 20.2% 65.1%))",
        },
        destructive: {
          DEFAULT: "hsl(var(--destructive, 0 62.8% 30.6%))",
          foreground: "hsl(var(--destructive-foreground, 210 40% 98%))",
        },
        accent: {
          DEFAULT: "hsl(var(--accent, 217.2 32.6% 17.5%))",
          foreground: "hsl(var(--accent-foreground, 210 40% 98%))",
        }
      },
      fontFamily: {
        mono: ["JetBrains Mono", "Fira Code", "Courier New", "monospace"],
      }
    },
  },
  plugins: [],
}
