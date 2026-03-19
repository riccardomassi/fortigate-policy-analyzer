/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        critical: '#c0392b',
        warning: '#e67e22',
        info: '#2980b9',
        success: '#27ae60',
      }
    },
  },
  plugins: [],
}
