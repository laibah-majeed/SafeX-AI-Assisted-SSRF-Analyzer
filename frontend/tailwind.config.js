/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      colors: {
        base: {
          DEFAULT: "#0B0F14",
          panel: "#121821",
          panelAlt: "#17202B",
          border: "#26313F",
        },
        ink: {
          DEFAULT: "#E6EDF3",
          muted: "#8B98A5",
          faint: "#5B6774",
        },
        signal: {
          DEFAULT: "#4FD1C5",
          dim: "#2F9E93",
        },
        severity: {
          low: "#34D399",
          medium: "#F5A524",
          high: "#F0576B",
          none: "#5B6774",
        },
      },
      fontFamily: {
        sans: ["Inter", "system-ui", "sans-serif"],
        mono: ["'IBM Plex Mono'", "ui-monospace", "SFMono-Regular", "monospace"],
      },
    },
  },
  plugins: [],
};
