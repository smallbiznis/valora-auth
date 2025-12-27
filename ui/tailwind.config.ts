import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        "bg-primary": "hsl(var(--bg-primary) / <alpha-value>)",
        "bg-surface": "hsl(var(--bg-surface) / <alpha-value>)",
        "bg-surface-strong": "hsl(var(--bg-surface-strong) / <alpha-value>)",
        "bg-subtle": "hsl(var(--bg-subtle) / <alpha-value>)",
        "border-subtle": "hsl(var(--border-subtle) / <alpha-value>)",
        "border-strong": "hsl(var(--border-strong) / <alpha-value>)",
        "text-primary": "hsl(var(--text-primary) / <alpha-value>)",
        "text-secondary": "hsl(var(--text-secondary) / <alpha-value>)",
        "text-muted": "hsl(var(--text-muted) / <alpha-value>)",
        "text-inverse": "hsl(var(--text-inverse) / <alpha-value>)",
        "accent-primary": "hsl(var(--accent-primary) / <alpha-value>)",
        "accent-glow": "hsl(var(--accent-glow) / <alpha-value>)",
        "status-success": "hsl(var(--status-success) / <alpha-value>)",
        "status-warning": "hsl(var(--status-warning) / <alpha-value>)",
        "status-error": "hsl(var(--status-error) / <alpha-value>)",
      },
      borderRadius: {
        sm: "var(--radius-sm)",
        md: "var(--radius-md)",
        lg: "var(--radius-lg)",
        xl: "var(--radius-xl)",
        "2xl": "var(--radius-2xl)",
        full: "var(--radius-pill)",
      },
      boxShadow: {
        xs: "var(--shadow-xs)",
        sm: "var(--shadow-sm)",
        md: "var(--shadow-md)",
        glow: "var(--shadow-glow)",
      },
      blur: {
        xs: "var(--blur-xs)",
        sm: "var(--blur-sm)",
        md: "var(--blur-md)",
        lg: "var(--blur-lg)",
      },
      backdropBlur: {
        xs: "var(--blur-xs)",
        sm: "var(--blur-sm)",
        md: "var(--blur-md)",
        lg: "var(--blur-lg)",
      },
      zIndex: {
        base: "var(--z-base)",
        header: "var(--z-header)",
        overlay: "var(--z-overlay)",
        modal: "var(--z-modal)",
        toast: "var(--z-toast)",
      },
      transitionDuration: {
        fast: "var(--motion-fast)",
        base: "var(--motion-base)",
        slow: "var(--motion-slow)",
      },
      transitionTimingFunction: {
        standard: "var(--motion-ease)",
        "ease-in-out": "var(--motion-ease-in-out)",
      },
      keyframes: {
        fade: {
          "0%": { opacity: "0" },
          "100%": { opacity: "1" },
        },
        "slide-up": {
          "0%": { opacity: "0", transform: "translateY(12px)" },
          "100%": { opacity: "1", transform: "translateY(0)" },
        },
        glow: {
          "0%": { opacity: "0.7" },
          "100%": { opacity: "1" },
        },
      },
      animation: {
        fade: "fade var(--motion-base) var(--motion-ease) both",
        "slide-up": "slide-up var(--motion-slow) var(--motion-ease) both",
        glow: "glow var(--motion-slow) var(--motion-ease-in-out) both",
      },
      fontFamily: {
        sans: ["var(--font-sans)"],
        mono: ["var(--font-mono)"],
      },
    },
  },
  plugins: [],
};

export default config;
