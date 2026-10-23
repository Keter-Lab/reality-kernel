/* The Warden watches every action, on every page.
   - A reticle trails the pointer. Over a link or button it locks onto the
     element's corners and names the system call the action would make (a link
     is a connect(), a button an execve()) with its verdict; buttons lean
     toward the pointer.
   - Labels decode from terminal glyphs as they scroll into view; serif
     headings ink in.
   - A boundary line under the header fills as you scroll, with the Warden
     riding it.
   - Once the hero is out of view, a small Warden perches in the corner; its
     eyes follow the pointer, its head tilts with the scroll, and clicking it
     switches the site mode.
   All decorative, off on touch screens (pointer effects) and with reduced
   motion. The system cursor always stays visible. */
(function () {
  const fine = window.matchMedia('(hover: hover) and (pointer: fine)');
  const reduced = window.matchMedia('(prefers-reduced-motion: reduce)');
  if (reduced.matches) return;
  const SVG = 'http://www.w3.org/2000/svg';
  const el = (ns, tag, attrs) => {
    const n = ns ? document.createElementNS(ns, tag) : document.createElement(tag);
    for (const k in attrs) n.setAttribute(k, attrs[k]);
    return n;
  };
  const mode = () => (window.rkMode ? window.rkMode.get() : 'enforce');
  const lerp = (a, b, k) => a + (b - a) * k;

  /* ── The watched cursor, with target lock ─────────────────────────── */
  function cursor() {
    if (!fine.matches) return;
    const ring = el(null, 'div', { class: 'rk-cursor', 'aria-hidden': 'true' });
    const tag = el(null, 'div', { class: 'rk-cursor-tag', 'aria-hidden': 'true' });
    document.body.append(ring, tag);
    let x = innerWidth / 2, y = innerHeight / 2, shown = false, lock = null;
    const box = { x, y, w: 28, h: 28 };

    function describe(target) {
      if (!target || !target.closest) return null;
      if (target.closest('.mode-switch, #hero-canvas, .mini-warden')) return 'write("mode")';
      const a = target.closest('a[href]');
      if (a) {
        const href = a.getAttribute('href') || '';
        if (href.startsWith('http')) {
          let host = href;
          try { host = new URL(href).host; } catch { /* keep raw */ }
          return 'connect(' + host + ':443)';
        }
        if (href.startsWith('mailto:')) return 'sendmsg(smtp)';
        return 'openat("' + (href.split('#')[0] || '/') + '")';
      }
      const b = target.closest('button');
      if (b) return 'execve("' + (b.textContent.trim().split(/\s+/)[0] || 'button').toLowerCase() + '")';
      if (target.closest('pre, code')) return 'read(fd, buf)';
      return null;
    }

    addEventListener('pointermove', e => {
      x = e.clientX; y = e.clientY;
      if (!shown) { shown = true; ring.classList.add('on'); }
      const call = describe(e.target);
      lock = e.target.closest ? e.target.closest('a[href], button') : null;
      ring.classList.toggle('lock', !!lock);
      if (call) {
        tag.textContent = call + ' \u00b7 allow' + (mode() === 'audit' ? ' \u00b7 logged' : '');
        tag.classList.add('on');
      } else {
        tag.classList.remove('on');
      }
    }, { passive: true });
    document.addEventListener('pointerleave', () => { shown = false; ring.classList.remove('on'); tag.classList.remove('on'); });
    addEventListener('pointerdown', () => ring.classList.add('press'));
    addEventListener('pointerup', () => ring.classList.remove('press'));

    (function loop() {
      let tx = x, ty = y, tw = 28, th = 28;
      if (lock && lock.isConnected) {
        const r = lock.getBoundingClientRect();
        tx = r.left + r.width / 2; ty = r.top + r.height / 2; tw = r.width + 12; th = r.height + 10;
      }
      box.x = lerp(box.x, tx, 0.24); box.y = lerp(box.y, ty, 0.24);
      box.w = lerp(box.w, tw, 0.24); box.h = lerp(box.h, th, 0.24);
      ring.style.width = box.w + 'px';
      ring.style.height = box.h + 'px';
      ring.style.transform = 'translate(' + (box.x - box.w / 2) + 'px,' + (box.y - box.h / 2) + 'px)';
      tag.style.transform = 'translate(' + (x + 18) + 'px,' + (y + 18) + 'px)';
      requestAnimationFrame(loop);
    })();
  }

  /* ── Magnetic buttons ─────────────────────────────────────────────── */
  function magnetic() {
    if (!fine.matches) return;
    document.querySelectorAll('.btn, .mode-switch').forEach(b => {
      b.addEventListener('pointermove', e => {
        const r = b.getBoundingClientRect();
        const dx = (e.clientX - (r.left + r.width / 2)) * 0.16, dy = (e.clientY - (r.top + r.height / 2)) * 0.26;
        b.style.transform = 'translate(' + dx.toFixed(1) + 'px,' + dy.toFixed(1) + 'px)';
      });
      b.addEventListener('pointerleave', () => { b.style.transform = ''; });
    });
  }

  /* ── Headings decode from terminal glyphs ─────────────────────────── */
  const GLYPHS = '01<>/\\{}[]#$%&*+=~:;|^';
  function decode(node) {
    const texts = [];
    const walk = document.createTreeWalker(node, NodeFilter.SHOW_TEXT);
    while (walk.nextNode()) if (walk.currentNode.nodeValue.trim()) texts.push(walk.currentNode);
    for (const t of texts) {
      const final = t.__rk || (t.__rk = t.nodeValue);
      const len = final.length, start = performance.now(), dur = 500 + len * 18;
      (function frame(now) {
        const p = Math.min(1, (now - start) / dur);
        let out = '';
        for (let i = 0; i < len; i++) {
          const ch = final[i];
          if (ch === ' ' || i / len < p * 1.15 - 0.15) out += ch;
          else out += GLYPHS[(Math.random() * GLYPHS.length) | 0];
        }
        t.nodeValue = p >= 1 ? final : out;
        if (p < 1) requestAnimationFrame(frame);
      })(start);
    }
  }
  // Serif type would break apart as glyphs, so it rises out of a blur instead.
  function inkIn(node) {
    if (!node.animate) return;
    node.animate([
      { opacity: 0, transform: 'translateY(0.3em)', filter: 'blur(8px)' },
      { opacity: 1, transform: 'none', filter: 'blur(0)' },
    ], { duration: 900, easing: 'cubic-bezier(.2,.7,.1,1)' });
  }
  function decoding() {
    if (!('IntersectionObserver' in window)) return;
    const io = new IntersectionObserver(es => {
      es.forEach(e => {
        if (!e.isIntersecting) return;
        (e.target.matches('.sigil') ? decode : inkIn)(e.target);
        io.unobserve(e.target);
      });
    });
    document.querySelectorAll('main h1, main h2, main .sigil').forEach(t => io.observe(t));
    document.addEventListener('rk:mode', () => {
      document.querySelectorAll('.tagline em').forEach(n => { if (n.offsetParent !== null) inkIn(n); });
      document.querySelectorAll('.watch-status > span').forEach(n => { if (n.offsetParent !== null) decode(n); });
    });
  }

  /* ── The boundary follows the page ────────────────────────────────── */
  function progress() {
    const bar = el(null, 'div', { class: 'rk-progress', 'aria-hidden': 'true' });
    const fill = el(null, 'span', { class: 'rk-progress-fill' });
    const rider = el(null, 'span', { class: 'rk-progress-rider' });
    bar.append(fill, rider);
    document.body.appendChild(bar);
    let p = 0, target = 0;
    const read = () => {
      const max = document.documentElement.scrollHeight - innerHeight;
      target = max > 0 ? Math.min(1, Math.max(0, scrollY / max)) : 0;
    };
    addEventListener('scroll', read, { passive: true });
    addEventListener('resize', read);
    read();
    (function loop() {
      p = lerp(p, target, 0.14);
      fill.style.transform = 'scaleX(' + p.toFixed(4) + ')';
      rider.style.transform = 'translateX(' + (p * (bar.clientWidth - 14)).toFixed(1) + 'px)';
      rider.style.opacity = p > 0.004 ? '1' : '0';
      requestAnimationFrame(loop);
    })();
  }

  /* ── The perched Warden ─────────────────────────────────────────── */
  function perch() {
    const box = el(null, 'button', { class: 'mini-warden', type: 'button', 'aria-label': 'The Warden: switch the site mode' });
    const svg = el(SVG, 'svg', { viewBox: '0 0 64 64', 'aria-hidden': 'true' });
    const head = el(SVG, 'g', {});
    const parts = [
      ['path', { d: 'M20 22 Q32 16 44 22 L48 34 Q50 52 32 58 Q14 52 16 34 Z', class: 'mw-body' }],
      ['path', { d: 'M14 14 L20 22 M50 14 L44 22', class: 'mw-line' }],
    ];
    for (const [t, a] of parts) head.appendChild(el(SVG, t, a));
    const eyes = [];
    for (const cx of [25, 39]) {
      head.appendChild(el(SVG, 'circle', { cx, cy: 31, r: 6, class: 'mw-line' }));
      const p = el(SVG, 'circle', { cx, cy: 31, r: 2.2, class: 'mw-eye' });
      head.appendChild(p);
      eyes.push({ node: p, cx });
    }
    head.appendChild(el(SVG, 'path', { d: 'M30 38 L32 42 L34 38', class: 'mw-line' }));
    head.appendChild(el(SVG, 'path', { d: 'M26 47 L29 49 L32 47 L35 49 L38 47', class: 'mw-line mw-faint' }));
    svg.appendChild(head);
    svg.appendChild(el(SVG, 'path', { d: 'M10 59 L54 59', class: 'mw-line' }));
    box.appendChild(svg);
    const label = el(null, 'span', { class: 'mw-label' });
    box.appendChild(label);
    document.body.appendChild(box);
    box.addEventListener('click', () => window.rkMode && window.rkMode.toggle());

    const sync = () => { label.textContent = 'warden · ' + mode(); };
    sync();
    document.addEventListener('rk:mode', sync);

    // Shown once the page's own Warden (the hero) is out of view.
    const hero = document.getElementById('hero-canvas');
    const show = on => box.classList.toggle('on', on);
    if (hero && 'IntersectionObserver' in window) {
      new IntersectionObserver(es => show(!es[0].isIntersecting)).observe(hero);
    } else {
      show(true);
    }

    let px = innerWidth / 2, py = innerHeight / 2, tilt = 0, lastY = scrollY;
    addEventListener('pointermove', e => { px = e.clientX; py = e.clientY; }, { passive: true });
    addEventListener('scroll', () => {
      const dy = scrollY - lastY;
      lastY = scrollY;
      tilt = Math.max(-14, Math.min(14, tilt + dy * 0.08));
    }, { passive: true });
    (function loop() {
      const r = box.getBoundingClientRect();
      const ox = r.left + r.width / 2, oy = r.top + r.height * 0.45;
      const ang = Math.atan2(py - oy, px - ox);
      const dist = Math.min(1, Math.hypot(px - ox, py - oy) / 300);
      for (const e of eyes) {
        e.node.setAttribute('cx', (e.cx + Math.cos(ang) * 2.6 * dist).toFixed(2));
        e.node.setAttribute('cy', (31 + Math.sin(ang) * 2.6 * dist).toFixed(2));
      }
      tilt *= 0.92;
      head.setAttribute('transform', 'rotate(' + tilt.toFixed(2) + ' 32 40)');
      requestAnimationFrame(loop);
    })();
  }

  function init() { cursor(); magnetic(); decoding(); progress(); perch(); }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init); else init();
})();
