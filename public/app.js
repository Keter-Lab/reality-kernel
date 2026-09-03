/* Reality Kernel Client Portal — shared client code (login + dashboard) */
(function () {
  const API_BASE = (location.hostname === 'localhost' || location.hostname === '127.0.0.1')
    ? (window.RK_API_BASE || 'http://localhost:8000')
    : '';

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
    if (key) headers['Authorization'] = 'Bearer ' + key;

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), opts.timeout || 30000);
      
      const r = await fetch(API_BASE + path, { ...opts, headers, signal: controller.signal });
      clearTimeout(timeoutId);

      if (r.status === 401 || r.status === 403) {
        if (sessionStorage.getItem('rk_preview_mode') === 'true') {
          return { ok: false, status: r.status, body: null, headers: r.headers };
        }
        clearKey();
        // FIX: redirect to /login not '/' so users land on the sign-in form
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
    // FIX: redirect to /login, not '/' (homepage)
    if (!getKey()) { location.href = '/login'; return false; }
    return true;
  }

  function logout() {
    clearKey();
    location.href = '/';
  }

  function fmtTime(ts) {
    if (!ts) return '—';
    const d = (typeof ts === 'number') ? new Date(ts * 1000) : new Date(ts);
    if (isNaN(d.getTime())) return String(ts);
    return d.toLocaleString();
  }
  function fmtNum(n) {
    if (n === null || n === undefined) return '—';
    return Number(n).toLocaleString();
  }

  window.rk = { 
    API_BASE, getKey, clearKey, call, verifyKey, requireKey, 
    logout, fmtTime, fmtNum, isPlausibleKey, htmlEscape, newIdempotencyKey 
  };

  /* ── Portal v2 shared behaviours ────────────────────────────────────── */

  // Minimal, dependency-free syntax highlighter for docs code blocks.
  // Operates on already-escaped text. Good enough for python/ts/bash/json.
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
    // Placeholders use private-use code points (no digits/letters) so later passes never re-tokenise them.
    const stash = (cls, txt) => { slots.push('<span class="' + cls + '">' + txt + '</span>'); return '\u0000' + String.fromCharCode(0xE000 + slots.length - 1) + '\u0000'; };
    const slotIdx = (ch) => ch.charCodeAt(0) - 0xE000;
    // comments
    if (lang === 'python' || lang === 'bash') s = s.replace(/(^|[^:\\])(#[^\n]*)/gm, (m, a, c) => a + stash('tk-c', c));
    if (lang === 'typescript') s = s.replace(/(\/\/[^\n]*)/g, (m) => stash('tk-c', m)).replace(/\/\*[\s\S]*?\*\//g, (m) => stash('tk-c', m));
    // strings (escaped quotes appear as &quot; / &#39;)
    s = s.replace(/(&quot;(?:(?!&quot;)[^\n])*&quot;|&#39;(?:(?!&#39;)[^\n])*&#39;|`[^`]*`)/g, (m) => stash('tk-s', m));
    // decorators / types
    if (lang === 'python') s = s.replace(/(^|\s)(@[\w.]+)/gm, (m, a, d) => a + stash('tk-t', d));
    // numbers
    s = s.replace(/\b(\d+(?:\.\d+)?)\b/g, (m) => stash('tk-n', m));
    // keywords
    if (KW[lang]) s = s.replace(KW[lang], (m, a, b) => (lang === 'bash' ? a + stash('tk-k', b) : stash('tk-k', m)));
    // function calls
    if (lang === 'python' || lang === 'typescript') s = s.replace(/\b([A-Za-z_][\w]*)(?=\()/g, (m) => stash('tk-f', m));
    // json keys
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
          } catch { /* clipboard blocked — no-op */ }
        });
      }
    });
  }

  function initTabs(root) {
    (root || document).querySelectorAll('.rk-tabs').forEach(group => {
      const tabs = group.querySelectorAll('.rk-tab');
      const panels = group.querySelectorAll('.rk-tabpanel');
      tabs.forEach((t, i) => t.addEventListener('click', () => {
        tabs.forEach(x => x.classList.remove('active'));
        panels.forEach(x => x.classList.remove('active'));
        t.classList.add('active');
        const target = t.dataset.tab ? group.querySelector('.rk-tabpanel[data-tab="' + t.dataset.tab + '"]') : panels[i];
        if (target) target.classList.add('active');
      }));
    });
  }

  function initHeader() {
    const header = document.querySelector('.rk-header');
    if (!header) return;

    const nav = header.querySelector('nav.rk-nav');
    if (nav && !nav.querySelector('a[href="/"]')) {
      const home = document.createElement('a');
      home.href = '/';
      home.textContent = 'Home';
      nav.insertAdjacentElement('afterbegin', home);
    }

    const path = location.pathname.replace(/\.html$/, '').replace(/\/$/, '') || '/';
    const alias = { '/integration': '/docs', '/integrate': '/docs', '/sdk': '/docs' };
    const cur = alias[path] || path;
    header.querySelectorAll('nav.rk-nav a').forEach(a => {
      const href = (a.getAttribute('href') || '').replace(/\/$/, '') || '/';
      if (href === cur || (href === '/docs' && cur === '/docs')) a.classList.add('active');
    });

    const toggle = header.querySelector('.rk-menu-toggle');
    if (toggle && nav) toggle.addEventListener('click', () => nav.classList.toggle('open'));

    // Signed-in visitors see the console, not the access CTA
    if (getKey()) {
      header.querySelectorAll('[data-auth="signin"]').forEach(a => { a.textContent = 'Operator Console'; a.href = '/dashboard'; });
      header.querySelectorAll('[data-auth="request"]').forEach(a => { a.style.display = 'none'; });
    }
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

  function applyRouteFallbackRedirects() {
    const route = location.pathname.replace(/\/$/, '') || '/';
    const redirects = {
      '/docs': '/integration',
      '/integrate': '/integration'
    };
    const target = redirects[route];
    if (!target) return;

    const is404Template = !!document.querySelector('.nf-wrap') || /404/.test(document.title);
    if (is404Template) {
      location.replace(target + location.hash);
    }
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
    enhanceCodeBlocks();
    initTabs();
    initScrollSpy();
    
    // 1. Update navigation auth button
    const navAuthBtn = document.getElementById('nav-auth-btn');
    if (navAuthBtn && isAuth) {
      navAuthBtn.textContent = 'Dashboard';
      navAuthBtn.href = '/dashboard';
    }

    // 2. Hide elements that shouldn't be seen when logged in (like "Get API Key" CTAs)
    if (isAuth) {
      document.querySelectorAll('.hide-on-auth').forEach(el => {
        el.style.display = 'none';
      });
    }

    // Elite-Tier Enhancements
    const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    initAgentCursor();

    // 3. Scroll Progress Bar
    const scrollProgress = document.getElementById('scrollProgress');
    if (scrollProgress && !prefersReducedMotion) {
      window.addEventListener('scroll', () => {
        const docHeight = document.documentElement.scrollHeight - window.innerHeight;
        const progress = (window.scrollY / docHeight) * 100;
        scrollProgress.style.width = Math.min(100, Math.max(0, progress)) + '%';
      }, { passive: true });
    }

    // 4. Reveal Animations
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

    // 5. Cmd+K Palette
    const cmdOverlay = document.getElementById('cmdOverlay');
    const cmdInput = document.getElementById('cmdInput');
    if (cmdOverlay && cmdInput) {
      document.addEventListener('keydown', (e) => {
        if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
          e.preventDefault();
          cmdOverlay.classList.add('active');
          requestAnimationFrame(() => {
            cmdOverlay.classList.add('show');
            cmdInput.focus();
          });
        }
        if (e.key === 'Escape' && cmdOverlay.classList.contains('active')) {
          closeCmdPalette();
        }
      });
      cmdOverlay.addEventListener('click', (e) => {
        if (e.target === cmdOverlay) closeCmdPalette();
      });
      function closeCmdPalette() {
        cmdOverlay.classList.remove('show');
        setTimeout(() => cmdOverlay.classList.remove('active'), 200);
      }
      
      const cmdResults = document.querySelectorAll('.cmd-result');
      let selectedCmdIndex = 0;
      cmdInput.addEventListener('keydown', (e) => {
        if (e.key === 'ArrowDown') {
          e.preventDefault();
          selectedCmdIndex = (selectedCmdIndex + 1) % cmdResults.length;
          updateCmdSelection();
        } else if (e.key === 'ArrowUp') {
          e.preventDefault();
          selectedCmdIndex = (selectedCmdIndex - 1 + cmdResults.length) % cmdResults.length;
          updateCmdSelection();
        } else if (e.key === 'Enter') {
          e.preventDefault();
          const href = cmdResults[selectedCmdIndex].getAttribute('data-href');
          if (href) location.href = href;
        }
      });
      cmdResults.forEach((res, idx) => {
        res.addEventListener('mouseover', () => {
          selectedCmdIndex = idx;
          updateCmdSelection();
        });
        res.addEventListener('click', () => {
          const href = res.getAttribute('data-href');
          if (href) location.href = href;
        });
      });
      function updateCmdSelection() {
        cmdResults.forEach((r, i) => r.classList.toggle('selected', i === selectedCmdIndex));
      }
    }

    // 6. Live Counter Ticker
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

    // 7. Terminal Theatre
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
        if (entries[0].isIntersecting) {
          theatreObserver.disconnect();
          setTimeout(() => runTerminalTheatre(), 500);
        }
      }, { threshold: 0.5 });
      theatreObserver.observe(termTheatre);

      async function runTerminalTheatre() {
        lines.forEach(l => l?.classList.remove('active'));
        if(lines[0]) lines[0].classList.add('active');
        if(termTyping) termTyping.textContent = '';
        
        for (let i = 0; i < command.length; i++) {
          if(termTyping) termTyping.textContent += command[i];
          await new Promise(r => setTimeout(r, 20 + Math.random() * 30));
        }
        
        await new Promise(r => setTimeout(r, 400));
        if(lines[1]) lines[1].classList.add('active');
        await new Promise(r => setTimeout(r, 150));
        if(lines[2]) lines[2].classList.add('active');
        await new Promise(r => setTimeout(r, 100));
        if(lines[3]) lines[3].classList.add('active');
      }
    }

  });
})();
