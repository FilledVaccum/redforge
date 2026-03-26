import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        paper:   { DEFAULT: "#F3F0E8", 2: "#ECEAE0", 3: "#E4E0D4" },
        ink:     { DEFAULT: "#0D0D0A", 2: "#2A2A24", 3: "#5C5C50", 4: "#9A9A88", 5: "#C8C8B4" },
        red:     { DEFAULT: "#CC2200", dark: "#A01A00" },
        surface: "#FDFBF4",
      },
      fontFamily: {
        display: ["'Barlow Condensed'", "sans-serif"],
        mono:    ["'IBM Plex Mono'", "monospace"],
        stat:    ["'Bebas Neue'", "cursive"],
      },
      fontSize: {
        "2xs": "0.625rem",
        "3xs": "0.5rem",
      },
      letterSpacing: {
        caps: "0.18em",
        wide2: "0.14em",
      },
    },
  },
  plugins: [],
};

export default config;
