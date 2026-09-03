/** Tailwind config for the light "Premium Clean Lab" landing interface. */
module.exports = {
  content: ['./public/index.html', './public/landing.js', './scripts/partials.py'],
  theme: {
    extend: {
      fontFamily: {
        sans: ['"Geist Sans"', 'Inter', 'ui-sans-serif', 'system-ui', '-apple-system', 'Segoe UI', 'sans-serif'],
        mono: ['"Geist Mono"', '"JetBrains Mono"', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'monospace'],
      },
      boxShadow: {
        card: '0 8px 30px rgb(0 0 0 / 0.02)',
        'card-hover': '0 12px 40px rgb(0 0 0 / 0.05)',
        window: '0 30px 80px -20px rgb(15 23 42 / 0.18), 0 8px 30px rgb(0 0 0 / 0.03)',
        glow: '0 0 0 4px rgb(16 185 129 / 0.12)',
        'glow-red': '0 0 0 4px rgb(239 68 68 / 0.14)',
      },
      keyframes: {
        'pulse-ring': { '0%': { transform: 'scale(0.85)', opacity: '0.55' }, '100%': { transform: 'scale(1.6)', opacity: '0' } },
        'ping-slow':  { '75%, 100%': { transform: 'scale(1.8)', opacity: '0' } },
        'float':      { '0%,100%': { transform: 'translateY(0)' }, '50%': { transform: 'translateY(-4px)' } },
        'dash':       { to: { strokeDashoffset: '-24' } },
        'fade-up':    { from: { opacity: '0', transform: 'translateY(10px)' }, to: { opacity: '1', transform: 'translateY(0)' } },
        'shake':      { '0%,100%': { transform: 'translateX(0)' }, '20%,60%': { transform: 'translateX(-2px)' }, '40%,80%': { transform: 'translateX(2px)' } },
      },
      animation: {
        'pulse-ring': 'pulse-ring 2.4s cubic-bezier(0.16,1,0.3,1) infinite',
        'ping-slow': 'ping-slow 2.6s cubic-bezier(0,0,0.2,1) infinite',
        float: 'float 5s ease-in-out infinite',
        dash: 'dash 1.2s linear infinite',
        'fade-up': 'fade-up .5s cubic-bezier(0.16,1,0.3,1) both',
        shake: 'shake .35s ease-in-out',
      },
    },
  },
  plugins: [],
};
