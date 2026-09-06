/* Reality Kernel Client Portal — shared client code (login + dashboard) */
(function () {
  const API_BASE = (location.hostname === 'localhost' || location.hostname === '127.0.0.1')
    ? (window.RK_API_BASE || 'http://localhost:8000')
    : ''

  /* ── Theme (light default, optional dark) ───────────────────────────────
     Applied as early as this script runs so the painted theme matches the
     stored preference. Only an explicit saved value flips to dark — the
     default is always the light interface. */
  const THEME_KEY = 'rk-theme';
  function storedTheme() {
    try { return localStorage.getItem(THEME_KEY); } catch { return null; }
  }
  function applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme === 'dark' ? 'dark' : 'light');
    const meta = document.querySelector('meta[name="theme-color"]');
    if (meta) meta.setAttribute('content', theme === 'dark' ? '#070c17' : '#f2f6fc');
  }
  applyTheme(storedTheme() === 'dark' ? 'dark' : 'light');

  const SUN_SVG = '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg>';
  const MOON_SVG = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/></svg>';
  function currentTheme() {
    return document.documentElement.getAttribute('data-theme') === 'dark' ? 'dark' : 'light';
  }
  function setTheme(theme, persist) {
    applyTheme(theme);
    if (persist) { try { localStorage.setItem(THEME_KEY, theme); } catch { /* ignore */ } }
    document.querySelectorAll('.rk-theme-toggle').forEach(syncToggle);
  }
  function syncToggle(btn) {
    const dark = currentTheme() === 'dark';
    btn.innerHTML = dark ? SUN_SVG : MOON_SVG;
    btn.setAttribute('aria-label', dark ? 'Switch to light theme' : 'Switch to dark theme');
    btn.setAttribute('aria-pressed', String(dark));
    btn.title = dark ? 'Light mode' : 'Dark mode';
  }
  function initThemeToggle() {
    document.querySelectorAll('.rk-header .rk-header-cta').forEach(cta => {
      if (cta.querySelector('.rk-theme-toggle')) return;
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'rk-theme-toggle';
      syncToggle(btn);
      btn.addEventListener('click', () => setTheme(currentTheme() === 'dark' ? 'light' : 'dark', true));
      cta.insertBefore(btn, cta.firstChild);
    });
    // Enable colour transitions only after the initial paint so first load
    // never animates from light → stored dark.
    requestAnimationFrame(() => document.documentElement.classList.add('theme-ready'));
  }

  function getKey() {
    return sessionStorage.getItem('rk_api_key') || localStorage.getItem('rk_api_key') || null;
  }
  function clearKey() {
    localStorage.removeItem('rk_api_key');
    sessionStorage.removeItem('rk_api_key');
  }

  function isPlausibleKey(k) {
    if (!k) return false;
    return /^[A-Za-z0-9_\-]{20,128}$/.test(k);
  }

  function htmlEscape(s) {
    return String(s).replace(/[&<>"']/g, c => ({
      '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'
    })[c]);
  }

  function newIdempotencyKey() {
    return 'idemp_' + Math.random().toString(36).slice(2) + Date.now().toString(36);
  }

  async function call(path, opts = {}) {
    const key = getKey();
    const headers = Object.assign({ 'Content-Type': 'application/json' }, opts.headers || {});
    if (key) headers['Authorization'] = 'Bearer ' + key
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), opts.timeout || 30000)
      const r = await fetch(API_BASE + path, { ...opts, headers, signal: controller.signal });
      clearTimeout(timeoutId)
      if (r.status === 401 || r.status === 403) {
        if (sessionStorage.getItem('rk_preview_mode') === 'true') {
          return { ok: false, status: r.status, body: null, headers: r.headers };
        }
        clearKey();
        if (location.pathname !== '/login' && !location.pathname.endsWith('login.html')) {
          location.href = '/login';
        }
      }
      let body = null;
      try { body = await r.json(); } catch { /* ignore */ }
      return { ok: r.ok, status: r.status, body, headers: r.headers };
    } catch (err) {
      console.error('RK.call error:', err);
      return { ok: false, status: 0, body: { detail: err.name === 'AbortError' ? 'Request timed out' : 'Network error' } };
    }
  }

  async function verifyKey(key) {
    if (!isPlausibleKey(key)) return false;
    try {
      const r = await fetch(API_BASE + '/v1/me', {
        headers: { 'Authorization': 'Bearer ' + key }
      });
      return r.ok;
    } catch { return false; }
  }

  function requireKey() {
    if (!getKey()) { location.href = '/login'; return false; }
    return true;
  }

  function logout() {
    clearKey();
    location.href = '/';
  }

  function fmtTime(ts) {
    if (!ts) return '\u2014';
    const d = (typeof ts === 'number') ? new Date(ts * 1000) : new Date(ts);
    if (isNaN(d.getTime())) return String(ts);
    return d.toLocaleString();
  }
  function fmtNum(n) {
    if (n === null || n === undefined) return '\u2014';
    return Number(n).toLocaleString();
  }

  window.rk = {
    API_BASE, getKey, clearKey, call, verifyKey, requireKey,
    logout, fmtTime, fmtNum, isPlausibleKey, htmlEscape, newIdempotencyKey
  }

  /* \u2500\u2500 Portal v2 shared behaviours \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500 */

  // Minimal, dependency-free syntax highlighter.
  const KW = {
    python: /\b(import|from|as|def|class|return|if|elif|else|for|while|in|not|and|or|is|None|True|False|try|except|finally|raise|with|lambda|yield|async|await|pass|break|continue|global|nonlocal|del|assert)\b/g,
    typescript: /\b(import|from|export|default|const|let|var|function|return|if|else|for|while|in|of|new|class|extends|interface|type|async|await|throw|try|catch|finally|switch|case|break|continue|typeof|instanceof|null|undefined|true|false|this|enum|implements|readonly|as|satisfies)\b/g,
    bash: /(^|\s)(export|if|then|else|fi|for|do|done|while|case|esac|function|local|return|exit|set|echo|curl|jq|python3?|node|npx|pip|npm)(?=\s|$)/gm,
    json: /\b(true|false|null)\b/g,
  };
  function highlight(src, lang) {
    lang = (lang || '').toLowerCase();
    if (lang === 'js' || lang === 'javascript' || lang === 'ts') lang = 'typescript';
    if (lang === 'sh' || lang === 'shell' || lang === 'curl') lang = 'bash';
    if (lang === 'py') lang = 'python';
    let s = htmlEscape(src);
    const slots = [];
    const stash = (cls, txt) => { slots.push('<span class="' + cls + '">' + txt + '</span>'); return '\u0000' + String.fromCharCode(0xE000 + slots.length - 1) + '\u0000'; };
    const slotIdx = (ch) => ch.charCodeAt(0) - 0xE000;
    if (lang === 'python' || lang === 'bash') s = s.replace(/(^|[^:\\])(#[^\n]*)/gm, (m, a, c) => a + stash('tk-c', c));
    if (lang === 'typescript') s = s.replace(/(\/\/[^\n]*)/g, (m) => stash('tk-c', m)).replace(/\/\*[\s\S]*?\*\//g, (m) => stash('tk-c', m));
    s = s.replace(/(&quot;(?:(?!&quot;)[^\n])*&quot;|&#39;(?:(?!&#39;)[^\n])*&#39;|`[^`]*`)/g, (m) => stash('tk-s', m));
    if (lang === 'python') s = s.replace(/(^|\s)(@[\w.]+)/gm, (m, a, d) => a + stash('tk-t', d));
    s = s.replace(/\b(\d+(?:\.\d+)?)\b/g, (m) => stash('tk-n', m));
    if (KW[lang]) s = s.replace(KW[lang], (m, a, b) => (lang === 'bash' ? a + stash('tk-k', b) : stash('tk-k', m)));
    if (lang === 'python' || lang === 'typescript') s = s.replace(/\b([A-Za-z_][\w]*)(?=\()/g, (m) => stash('tk-f', m));
    if (lang === 'json') s = s.replace(/\u0000([\uE000-\uF8FF])\u0000(?=\s*:)/g, (m, ch) => { const i = slotIdx(ch); slots[i] = slots[i].replace('tk-s', 'tk-k'); return m; });
    return s.replace(/\u0000([\uE000-\uF8FF])\u0000/g, (m, ch) => slots[slotIdx(ch)]);
  }

  function enhanceCodeBlocks(root) {
    (root || document).querySelectorAll('.rk-code').forEach(block => {
      const pre = block.querySelector('pre');
      if (!pre || block.dataset.enhanced) return;
      block.dataset.enhanced = '1';
      const codeEl = pre.querySelector('code') || pre;
      const raw = codeEl.textContent.replace(/^\n+|\n+$/g, '');
      codeEl.textContent = raw;
      const lang = block.dataset.lang || '';
      if (lang && !block.dataset.nohl) codeEl.innerHTML = highlight(raw, lang);
      const btn = block.querySelector('.rk-copy');
      if (btn) {
        btn.addEventListener('click', async () => {
          try {
            await navigator.clipboard.writeText(raw);
            btn.classList.add('copied');
            const label = btn.querySelector('span'); const prev = label ? label.textContent : '';
            if (label) label.textContent = 'Copied';
            setTimeout(() => { btn.classList.remove('copied'); if (label) label.textContent = prev || 'Copy'; }, 1600);
          } catch { /* clipboard blocked */ }
        });
      }
    });
  }

  function initTabs(root) {
    (root || document).querySelectorAll('.rk-tabs').forEach(group => {
      const tabs = Array.from(group.querySelectorAll('.rk-tab'));
      const panels = Array.from(group.querySelectorAll('.rk-tabpanel'));
      if (!tabs.length || !panels.length) return;
      const activate = (tab, index) => {
        tabs.forEach(x => { x.classList.remove('active'); x.setAttribute('aria-selected', 'false'); x.setAttribute('tabindex', '-1'); });
        panels.forEach(x => { x.classList.remove('active'); x.hidden = true; });
        tab.classList.add('active'); tab.setAttribute('aria-selected', 'true'); tab.setAttribute('tabindex', '0');
        const byDataTab = tab.dataset.tab ? group.querySelector('.rk-tabpanel[data-tab="' + tab.dataset.tab + '"]') : null;
        const target = byDataTab || panels[index] || null;
        if (target) { target.classList.add('active'); target.hidden = false; }
      };
      tabs.forEach((t, i) => t.addEventListener('click', () => activate(t, i)));
      const activeTab = tabs.find(t => t.classList.contains('active')) || tabs[0];
      activate(activeTab, tabs.indexOf(activeTab));
    });
  }

  // FIX: nav was undefined — query it inside the function scope
  function initHeader() {
    const header = document.querySelector('.rk-header');
    if (!header) return;
    const nav = header.querySelector('nav.rk-nav'); // FIX: was undefined, breaking mobile menu
    const path = location.pathname.replace(/\.html$/, '').replace(/\/$/, '') || '/';
    const alias = { '/integration': '/docs', '/integrate': '/docs', '/sdk': '/docs' };
    const cur = alias[path] || path;
    header.querySelectorAll('nav.rk-nav a').forEach(a => {
      const href = (a.getAttribute('href') || '').replace(/\/$/, '') || '/';
      if (href === cur || (href === '/docs' && cur === '/docs')) a.classList.add('active');
    });
    const toggle = header.querySelector('.rk-menu-toggle');
    if (toggle && nav) {
      toggle.setAttribute('aria-expanded', 'false');
      toggle.addEventListener('click', () => {
        const isOpen = nav.classList.toggle('open');
        toggle.setAttribute('aria-expanded', isOpen ? 'true' : 'false');
      });
      // Close nav when a link is clicked on mobile
      nav.querySelectorAll('a').forEach(a => {
        a.addEventListener('click', () => {
          nav.classList.remove('open');
          toggle.setAttribute('aria-expanded', 'false');
        });
      });
      // Close on outside click
      document.addEventListener('click', (e) => {
        if (!header.contains(e.target) && nav.classList.contains('open')) {
          nav.classList.remove('open');
          toggle.setAttribute('aria-expanded', 'false');
        }
      });
    }
    // Signed-in visitors: show Dashboard, hide Request Access
    if (getKey()) {
      header.querySelectorAll('[data-auth="signin"]').forEach(a => { a.textContent = 'Dashboard'; a.href = '/dashboard'; });
      header.querySelectorAll('[data-auth="request"]').forEach(a => { a.style.display = 'none'; });
    }
  }

  function applyTheme(theme) {
    const root = document.documentElement;
    root.setAttribute('data-theme', theme);
    root.classList.add('theme-ready');
  }

  function initThemeToggle() {
    const root = document.documentElement;
    const stored = localStorage.getItem('rk_theme') || localStorage.getItem('rk-theme');
    const prefersDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
    const theme = stored || (prefersDark ? 'dark' : 'light');
    applyTheme(theme);

    const toggleHost = document.querySelector('.rk-header .rk-header-cta, .operator-header .op-actions');
    if (!toggleHost || toggleHost.querySelector('.rk-theme-toggle')) return;

    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'rk-theme-toggle btn btn-sm ghost';
    btn.setAttribute('aria-label', 'Toggle dark mode');

    const icon = document.createElement('span');
    icon.className = 'rk-theme-toggle-icon';

    const moon = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M21 12.79A9 9 0 1 1 11.21 3c0 .34-.02.67-.02 1a7 7 0 0 0 8.81 6.79z"></path></svg>';
    const sun = '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="4"></circle><path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41"></path></svg>';

    const syncIcon = () => {
      const current = root.getAttribute('data-theme') || 'light';
      const dark = current === 'dark';
      icon.innerHTML = dark ? sun : moon;
      btn.setAttribute('aria-pressed', String(dark));
      btn.setAttribute('title', dark ? 'Switch to light mode' : 'Switch to dark mode');
    };

    btn.appendChild(icon);
    btn.addEventListener('click', () => {
      const current = root.getAttribute('data-theme') || 'light';
      const next = current === 'dark' ? 'light' : 'dark';
      applyTheme(next);
      localStorage.setItem('rk_theme', next);
      localStorage.setItem('rk-theme', next);
      syncIcon();
    });

    syncIcon();
    const menuToggle = toggleHost.querySelector('.rk-menu-toggle');
    if (menuToggle) toggleHost.insertBefore(btn, menuToggle);
    else toggleHost.appendChild(btn);
  }

  function buildList(ul, items, linkClass = '') {
    if (!ul) return;
    const classAttr = linkClass ? ' class="' + linkClass + '"' : '';
    ul.innerHTML = items.map((item) => {
      const external = item.external ? ' target="_blank" rel="noopener"' : '';
      return '<li><a href="' + item.href + '"' + classAttr + external + '>' + item.label + '</a></li>';
    }).join('');
  }

  function upsertSocialRow(target) {
    if (!target) return;
    target.classList.add('rk-footer-social');
    target.innerHTML = [
      '<a href="mailto:contact@realitykernel.dev" aria-label="Email Reality Kernel" title="Email">',
      '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 6h16a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2zm0 2 8 5 8-5"></path></svg>',
      '</a>',
      '<a href="https://www.linkedin.com/company/keter-labs/" target="_blank" rel="noopener" aria-label="Reality Kernel on LinkedIn" title="LinkedIn">',
      '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M6.94 8.5A1.56 1.56 0 1 1 6.93 5.4a1.56 1.56 0 0 1 .01 3.1zM5.5 9.75h2.88V19H5.5V9.75zm5.07 0h2.76v1.26h.04c.38-.72 1.33-1.48 2.74-1.48 2.93 0 3.47 1.93 3.47 4.45V19h-2.88v-4.44c0-1.06-.02-2.42-1.47-2.42-1.47 0-1.69 1.15-1.69 2.34V19h-2.88V9.75z"></path></svg>',
      '</a>'
    ].join('');
  }

  function initFooterLegalLinks() {
    const productLinks = [
      { href: '/playground', label: 'Playground' },
      { href: '/verifier', label: 'Verifier' },
      { href: '/pricing', label: 'Pricing' },
      { href: '/benchmark', label: 'Benchmark' },
      { href: '/security', label: 'Security & threat model' },
    ];
    const developerLinks = [
      { href: '/integration', label: 'Integration guide' },
      { href: '/sdk', label: 'SDK reference' },
      { href: '/integration#api', label: 'API reference' },
      { href: '/login#request', label: 'Request sandbox' },
    ];
    const trustLinks = [
      { href: '/about', label: 'About' },
      { href: '/privacy', label: 'Privacy policy' },
      { href: '/terms', label: 'Terms & conditions' },
      { href: '/cookies', label: 'Cookie policy' },
      { href: '/faq', label: 'FAQ' },
    ];

    document.querySelectorAll('.rk-footer').forEach((footer) => {
      const groups = Array.from(footer.querySelectorAll('h5'));
      const productHead = groups.find(h => h.textContent.trim().toLowerCase() === 'product');
      const developerHead = groups.find(h => h.textContent.trim().toLowerCase() === 'developers');
      const trustHead = groups.find(h => h.textContent.trim().toLowerCase() === 'trust');
      buildList(productHead && productHead.nextElementSibling, productLinks);
      buildList(developerHead && developerHead.nextElementSibling, developerLinks);
      buildList(trustHead && trustHead.nextElementSibling, trustLinks);

      const bottom = footer.querySelector('.rk-footer-bottom');
      if (bottom) {
        const spans = bottom.querySelectorAll(':scope > span');
        if (spans[0]) spans[0].textContent = '© 2026 Reality Kernel · All rights reserved';
        if (spans[1]) upsertSocialRow(spans[1]);
        else {
          const social = document.createElement('span');
          upsertSocialRow(social);
          bottom.appendChild(social);
        }
      }
    });

    const lightFooter = document.querySelector('footer.border-t.border-slate-200\\/80.bg-white');
    if (lightFooter) {
      const colHeadings = Array.from(lightFooter.querySelectorAll('h5'));
      const productHead = colHeadings.find(h => h.textContent.trim().toLowerCase() === 'product');
      const developerHead = colHeadings.find(h => h.textContent.trim().toLowerCase() === 'developers');
      const trustHead = colHeadings.find(h => h.textContent.trim().toLowerCase() === 'trust');
      const lightLinkClass = 'text-slate-600 hover:text-slate-900';
      buildList(productHead && productHead.nextElementSibling, productLinks, lightLinkClass);
      buildList(developerHead && developerHead.nextElementSibling, developerLinks, lightLinkClass);
      buildList(trustHead && trustHead.nextElementSibling, trustLinks, lightLinkClass);

      const bottomRow = lightFooter.querySelector('.mx-auto.flex.max-w-7xl');
      if (bottomRow) {
        const first = bottomRow.querySelector(':scope > span:first-child');
        const second = bottomRow.querySelector(':scope > span:last-child');
        if (first) first.textContent = '© 2026 Reality Kernel · All rights reserved';
        if (second) upsertSocialRow(second);
      }
    }
  }

  function applyRouteFallbackRedirects() {
    if (location.pathname.endsWith('.html')) {
      const clean = location.pathname.replace(/\.html$/, '');
      try { history.replaceState(null, '', clean + location.search + location.hash); } catch (e) { /* ignore */ }
    }

    const route = location.pathname.replace(/\/$/, '') || '/';
    const redirects = {
      '/docs': '/integration',
      '/integrate': '/integration'
    };
    const target = redirects[route];
    if (!target) return;

    const is404Template = !!document.querySelector('.nf-wrap') || /404/.test(document.title);
    if (is404Template) location.replace(target + location.hash);
  }

  function initAgentCursor() {
    if (!window.matchMedia || window.matchMedia('(pointer: coarse)').matches) return;
    const root = document.body;
    if (!root || root.querySelector('.agent-cursor')) return;

    const dot = document.createElement('div');
    dot.className = 'agent-cursor';
    root.appendChild(dot);
    root.classList.add('has-agent-cursor');

    let raf = 0;
    let x = window.innerWidth / 2;
    let y = window.innerHeight / 2;

    const paint = () => {
      dot.style.left = x + 'px';
      dot.style.top = y + 'px';
      raf = 0;
    };

    paint();
    dot.classList.add('active');

    const onPointerMove = (e) => {
      x = e.clientX;
      y = e.clientY;
      dot.classList.add('active');
      if (!raf) raf = requestAnimationFrame(paint);
    };

    window.addEventListener('pointermove', onPointerMove, { passive: true });
    window.addEventListener('mousedown', () => dot.classList.add('clicking'));
    window.addEventListener('mouseup', () => dot.classList.remove('clicking'));
    window.addEventListener('blur', () => dot.classList.remove('active'));
    window.addEventListener('focus', () => dot.classList.add('active'));
  }

  function initScrollSpy() {
    const side = document.querySelector('.docs-side');
    if (!side) return;
    const links = Array.from(side.querySelectorAll('a[href^="#"]'));
    const targets = links.map(l => document.getElementById(l.getAttribute('href').slice(1))).filter(Boolean);
    if (!targets.length) return;
    const obs = new IntersectionObserver((entries) => {
      entries.forEach(e => {
        if (e.isIntersecting) {
          links.forEach(l => l.classList.toggle('active', l.getAttribute('href') === '#' + e.target.id));
        }
      });
    }, { rootMargin: '-20% 0px -70% 0px', threshold: 0 });
    targets.forEach(t => obs.observe(t));
  }

  window.rk.highlight = highlight;
  window.rk.enhanceCodeBlocks = enhanceCodeBlocks;

  document.addEventListener('DOMContentLoaded', () => {
    const isAuth = !!getKey();
    applyRouteFallbackRedirects();
    initHeader();
    initThemeToggle();
    enhanceCodeBlocks();
    initTabs();
    initScrollSpy();

    const navAuthBtn = document.getElementById('nav-auth-btn');
    if (navAuthBtn && isAuth) {
      navAuthBtn.textContent = 'Dashboard';
      navAuthBtn.href = '/dashboard';
    }

    if (isAuth) {
      document.querySelectorAll('.hide-on-auth').forEach(el => { el.style.display = 'none'; });
    }

    const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    initAgentCursor();

    // Scroll Progress Bar
    const scrollProgress = document.getElementById('scrollProgress');
    if (scrollProgress && !prefersReducedMotion) {
      window.addEventListener('scroll', () => {
        const docHeight = document.documentElement.scrollHeight - window.innerHeight;
        const progress = (window.scrollY / docHeight) * 100;
        scrollProgress.style.width = Math.min(100, Math.max(0, progress)) + '%';
      }, { passive: true });
    }

    // Reveal Animations
    if (!prefersReducedMotion) {
      const observer = new IntersectionObserver((entries) => {
        entries.forEach(e => {
          if (e.isIntersecting) {
            e.target.classList.add('reveal-in');
            observer.unobserve(e.target);
          }
        });
      }, { threshold: 0.1, rootMargin: '0px 0px -50px 0px' });
      document.querySelectorAll('.reveal').forEach(el => observer.observe(el));
    } else {
      document.querySelectorAll('.reveal').forEach(el => el.classList.add('reveal-in'));
    }

    // Cmd+K Palette
    const cmdOverlay = document.getElementById('cmdOverlay');
    const cmdInput = document.getElementById('cmdInput');
    if (cmdOverlay && cmdInput) {
      document.addEventListener('keydown', (e) => {
        if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
          e.preventDefault();
          cmdOverlay.classList.add('active');
          requestAnimationFrame(() => { cmdOverlay.classList.add('show'); cmdInput.focus(); });
        }
        if (e.key === 'Escape' && cmdOverlay.classList.contains('active')) closeCmdPalette();
      });
      cmdOverlay.addEventListener('click', (e) => { if (e.target === cmdOverlay) closeCmdPalette(); });
      function closeCmdPalette() {
        cmdOverlay.classList.remove('show');
        setTimeout(() => cmdOverlay.classList.remove('active'), 200);
      }
      const cmdResults = document.querySelectorAll('.cmd-result');
      let selectedCmdIndex = 0;
      cmdInput.addEventListener('keydown', (e) => {
        if (e.key === 'ArrowDown') { e.preventDefault(); selectedCmdIndex = (selectedCmdIndex + 1) % cmdResults.length; updateCmdSelection(); }
        else if (e.key === 'ArrowUp') { e.preventDefault(); selectedCmdIndex = (selectedCmdIndex - 1 + cmdResults.length) % cmdResults.length; updateCmdSelection(); }
        else if (e.key === 'Enter') { e.preventDefault(); const href = cmdResults[selectedCmdIndex].getAttribute('data-href'); if (href) location.href = href; }
      });
      cmdResults.forEach((res, idx) => {
        res.addEventListener('mouseover', () => { selectedCmdIndex = idx; updateCmdSelection(); });
        res.addEventListener('click', () => { const href = res.getAttribute('data-href'); if (href) location.href = href; });
      });
      function updateCmdSelection() {
        cmdResults.forEach((r, i) => r.classList.toggle('selected', i === selectedCmdIndex));
      }
    }

    // Live Counter Ticker
    const navLiveStats = document.getElementById('navLiveStats');
    if (navLiveStats && !prefersReducedMotion) {
      let currentBlocks = 1402;
      setInterval(() => {
        if (Math.random() > 0.4) {
          currentBlocks += Math.floor(Math.random() * 5) + 1;
          navLiveStats.textContent = currentBlocks.toLocaleString();
        }
      }, 2000);
    }

    // Terminal Theatre
    const termTheatre = document.getElementById('terminalTheatre');
    if (termTheatre && !prefersReducedMotion) {
      const termTyping = document.getElementById('termTyping');
      const lines = [
        document.getElementById('termLine1'),
        document.getElementById('termLine2'),
        document.getElementById('termLine3'),
        document.getElementById('termLine4')
      ];
      const command = 'curl -H "X-aws-ec2-metadata-token: $(cat token.txt)" http://169.254.169.254/latest/';
      let theatreObserver = new IntersectionObserver((entries) => {
        if (entries[0].isIntersecting) { theatreObserver.disconnect(); setTimeout(() => runTerminalTheatre(), 500); }
      }, { threshold: 0.5 });
      theatreObserver.observe(termTheatre);
      async function runTerminalTheatre() {
        lines.forEach(l => l?.classList.remove('active'));
        if (lines[0]) lines[0].classList.add('active');
        if (termTyping) termTyping.textContent = '';
        for (let i = 0; i < command.length; i++) {
          if (termTyping) termTyping.textContent += command[i];
          await new Promise(r => setTimeout(r, 20 + Math.random() * 30));
        }
        await new Promise(r => setTimeout(r, 400));
        if (lines[1]) lines[1].classList.add('active');
        await new Promise(r => setTimeout(r, 150));
        if (lines[2]) lines[2].classList.add('active');
        await new Promise(r => setTimeout(r, 100));
        if (lines[3]) lines[3].classList.add('active');
      }
    }
  });
})()
