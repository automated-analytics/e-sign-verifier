const plugin = require("tailwindcss/plugin");

/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./app/**/*.{ts,tsx}", "./components/**/*.{ts,tsx}"],
  theme: {
    extend: {
      fontFamily: {
        sans: [
          "ui-sans-serif",
          "system-ui",
          "-apple-system",
          "Segoe UI",
          "Roboto",
          "Helvetica Neue",
          "sans-serif",
        ],
      },
      // Brand blue, taken from the logo (azure -> deep blue gradient). Single source of truth
      // for the product accent; buttons/links/steps all key off `brand-*`. The 600/700 steps
      // are AA-safe with white text (mirrors Tailwind's blue ramp).
      colors: {
        brand: {
          50: "#eff6ff",
          100: "#dbeafe",
          200: "#bfdbfe",
          300: "#93c5fd",
          400: "#60a5fa",
          500: "#3b82f6",
          600: "#2563eb",
          700: "#1d4ed8",
          800: "#1e40af",
          900: "#1e3a8a",
        },
      },
      backgroundImage: {
        // The logo's azure->blue sweep, reused for hero marks and primary emphasis.
        "brand-gradient": "linear-gradient(135deg, #38bdf8 0%, #2563eb 55%, #1d4ed8 100%)",
      },
      // Restrained, state-conveying entrances only (no bounce/elastic - this is a legal
      // instrument). ease-out-expo is confident and decisive; fill-mode stays `none` so if
      // the animation never runs (reduced-motion, headless render) the element is simply
      // visible at rest, never stuck hidden. The reduced-motion media query in globals.css
      // neutralizes all of these.
      keyframes: {
        "rise-in": {
          from: { opacity: "0", transform: "translateY(6px)" },
          to: { opacity: "1", transform: "translateY(0)" },
        },
        "scale-in": {
          from: { opacity: "0", transform: "scale(0.8)" },
          to: { opacity: "1", transform: "scale(1)" },
        },
      },
      animation: {
        "rise-in": "rise-in 220ms cubic-bezier(0.16, 1, 0.3, 1)",
        "scale-in": "scale-in 300ms cubic-bezier(0.16, 1, 0.3, 1)",
      },
    },
  },
  plugins: [
    // Input-method targeting so touch devices get 44px tap targets without inflating the
    // dense fine-pointer (mouse) layouts. Not in Tailwind 3.4 core, so registered here.
    plugin(({ addVariant }) => {
      addVariant("pointer-coarse", "@media (pointer: coarse)");
    }),
  ],
};
