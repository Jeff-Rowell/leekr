/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./src/**/*.{js,ts,jsx,tsx,html}",
  ],
  theme: {
    extend: {
      colors: {
        bgDark: '#1E1E1E',
        textVibrant: '#FFA726',
        leekGreen: '#A8C256',
        leekRoot: '#F5E0A3',
        blush: '#F28C8C',
        hoodieDark: '#4A4A4A',
        magnifyBlue: '#D0ECF0',
        borderDark: '#3A3A3A',
      },
      fontFamily: {
        leekr: ['Segoe UI', 'Roboto', 'sans-serif'],
      },
      borderRadius: {
        lgx: '10px',
      },
    },
  },
  plugins: [],
}
