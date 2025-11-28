// tailwind.config.js

/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}", // <-- Important line
  ],
  theme: {
    extend: {},
  },
  plugins: [],
}
