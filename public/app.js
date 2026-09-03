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

  document.addEventListener('DOMContentLoaded', () => {
    const isAuth = !!getKey();
    
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
