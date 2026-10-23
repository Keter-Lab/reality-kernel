/* Reality Kernel website: the site mode, navigation and copy buttons.
   Loaded in <head> so the saved mode applies before the first paint.
   The site is static: this script makes no network requests. */
(function () {
  if (location.hostname === 'realitykernel.dev') {
    location.replace('https://www.realitykernel.dev' + location.pathname + location.search + location.hash);
    return;
  }

  const root = document.documentElement;
  root.classList.add('js');

  /* ── Mode: the site runs in `enforce` or `audit`, like a profile does. ── */
  const KEY = 'rk-mode';
  function saved() {
    try { const m = localStorage.getItem(KEY); return m === 'audit' || m === 'enforce' ? m : null; } catch { return null; }
  }
  function current() { return root.getAttribute('data-mode') === 'audit' ? 'audit' : 'enforce'; }
  root.setAttribute('data-mode', saved() || (root.getAttribute('data-mode') === 'audit' ? 'audit' : 'enforce'));

  function syncSwitches() {
    const m = current();
    document.querySelectorAll('[data-mode-switch]').forEach(btn => {
      btn.setAttribute('aria-checked', String(m === 'enforce'));
      const v = btn.querySelector('.mode-value');
      if (v) v.textContent = m;
      btn.title = m === 'enforce' ? 'Switch to audit mode' : 'Switch to enforce mode';
    });
  }
  function setMode(m) {
    root.setAttribute('data-mode', m);
    try { localStorage.setItem(KEY, m); } catch { /* storage blocked: the choice lasts for this page */ }
    syncSwitches();
    document.dispatchEvent(new CustomEvent('rk:mode', { detail: m }));
  }
  window.rkMode = {
    get: current,
    toggle: () => setMode(current() === 'enforce' ? 'audit' : 'enforce'),
  };
  function initMode() {
    document.querySelectorAll('[data-mode-switch]').forEach(btn => btn.addEventListener('click', window.rkMode.toggle));
    syncSwitches();
    // Colour transitions only after the first paint, so loading never animates.
    requestAnimationFrame(() => root.classList.add('mode-ready'));
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

  /* ── Sections ease into place as they scroll in (visible without JS). ── */
  function initReveal() {
    const items = document.querySelectorAll('.reveal');
    if (!items.length) return;
    if (!('IntersectionObserver' in window) || window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
      items.forEach(el => el.classList.add('in'));
      return;
    }
    const io = new IntersectionObserver(entries => {
      entries.forEach(e => { if (e.isIntersecting) { e.target.classList.add('in'); io.unobserve(e.target); } });
    }, { rootMargin: '0px 0px -8% 0px' });
    items.forEach(el => io.observe(el));
  }

  /* ── /about.html is shown as /about. ── */
  function cleanUrl() {
    if (!location.pathname.endsWith('.html') || location.pathname.endsWith('/index.html')) return;
    try { history.replaceState(null, '', location.pathname.replace(/\.html$/, '') + location.search + location.hash); } catch { /* ignore */ }
  }

  document.addEventListener('DOMContentLoaded', () => {
    cleanUrl();
    initMode();
    initNav();
    initCopy();
    initReveal();
  });
})();
