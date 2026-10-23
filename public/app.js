/* Reality Kernel website: theme, navigation and copy buttons.
   Loaded in <head> so the saved theme applies before the first paint.
   The site is static: this script makes no network requests. */
(function () {
  if (location.hostname === 'realitykernel.dev') {
    location.replace('https://www.realitykernel.dev' + location.pathname + location.search + location.hash);
    return;
  }

  /* ── Theme: follows the system unless the visitor picked one. ── */
  const KEY = 'rk-theme';
  const root = document.documentElement;
  function saved() {
    try { const t = localStorage.getItem(KEY); return t === 'dark' || t === 'light' ? t : null; } catch { return null; }
  }
  function effective() {
    const t = root.getAttribute('data-theme');
    if (t) return t;
    return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  }
  const initial = saved();
  if (initial) root.setAttribute('data-theme', initial);

  const SUN = '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg>';
  const MOON = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/></svg>';
  function sync(btn) {
    const dark = effective() === 'dark';
    btn.innerHTML = dark ? SUN : MOON;
    btn.setAttribute('aria-label', dark ? 'Switch to light theme' : 'Switch to dark theme');
    btn.setAttribute('aria-pressed', String(dark));
  }
  function initTheme() {
    const host = document.querySelector('.header-actions');
    if (!host) return;
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'icon-btn theme-toggle';
    sync(btn);
    btn.addEventListener('click', () => {
      const next = effective() === 'dark' ? 'light' : 'dark';
      root.setAttribute('data-theme', next);
      try { localStorage.setItem(KEY, next); } catch { /* storage blocked: the choice lasts for this page */ }
      sync(btn);
    });
    window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => sync(btn));
    host.insertBefore(btn, host.querySelector('.menu-toggle'));
    requestAnimationFrame(() => root.classList.add('theme-ready'));
  }

  /* ── Navigation: current page and the mobile menu. ── */
  function initNav() {
    const nav = document.getElementById('site-nav');
    if (!nav) return;
    const path = location.pathname.replace(/\.html$/, '').replace(/\/$/, '') || '/';
    nav.querySelectorAll('a').forEach(a => {
      if ((a.getAttribute('href') || '') === path) {
        a.classList.add('active');
        a.setAttribute('aria-current', 'page');
      }
    });
    const toggle = document.querySelector('.menu-toggle');
    if (!toggle) return;
    const set = open => { nav.classList.toggle('open', open); toggle.setAttribute('aria-expanded', String(open)); };
    toggle.addEventListener('click', () => set(!nav.classList.contains('open')));
    nav.addEventListener('click', e => { if (e.target.closest('a')) set(false); });
    document.addEventListener('keydown', e => { if (e.key === 'Escape') set(false); });
  }

  /* ── Copy buttons on code blocks. ── */
  function initCopy() {
    document.querySelectorAll('.code').forEach(block => {
      const btn = block.querySelector('.copy');
      const pre = block.querySelector('pre');
      if (!btn || !pre) return;
      btn.addEventListener('click', async () => {
        const text = pre.innerText.split('\n').filter(l => !l.trimStart().startsWith('#')).join('\n').trim();
        try {
          await navigator.clipboard.writeText(text);
          btn.textContent = 'Copied';
        } catch {
          const range = document.createRange();
          range.selectNodeContents(pre);
          const sel = window.getSelection();
          sel.removeAllRanges();
          sel.addRange(range);
          btn.textContent = 'Selected';
        }
        setTimeout(() => { btn.textContent = 'Copy'; }, 1600);
      });
    });
  }

  /* ── /about.html is shown as /about. ── */
  function cleanUrl() {
    if (!location.pathname.endsWith('.html') || location.pathname.endsWith('/index.html')) return;
    try { history.replaceState(null, '', location.pathname.replace(/\.html$/, '') + location.search + location.hash); } catch { /* ignore */ }
  }

  document.addEventListener('DOMContentLoaded', () => {
    cleanUrl();
    initTheme();
    initNav();
    initCopy();
  });
})();
