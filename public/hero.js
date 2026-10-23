/* The home page's hero: the Warden, Reality Kernel's guardian owl, perched
   on the kernel boundary. System calls rise from user space. Allowed calls
   pass into the kernel; a denied call is knocked back with -1 EPERM in
   enforce mode, or let through and logged as a would-deny in audit mode, as a
   real profile behaves. Click the owl to switch modes. Decorative only (the
   canvas is aria-hidden; the header switch is the accessible control); with
   reduced motion it draws one still frame. Colours come from CSS variables. */
(function () {
  const canvas = document.getElementById('hero-canvas');
  if (!canvas || !canvas.getContext) return;
  const ctx = canvas.getContext('2d');
  const reduced = window.matchMedia('(prefers-reduced-motion: reduce)');

  const CALLS = ['connect()', 'execve()', 'openat()', 'sendmsg()', 'unlink()', 'rename()',
                 'socket()', 'bpf()', 'kill()', 'ptrace()', 'linkat()', 'setattr()'];
  let W = 0, H = 0, line = 0, u = 1, lanes = [];
  let calls = [], shards = [], marks = [];
  let colors = {}, mode = 'enforce', last = 0, running = false, visible = true, t = 0;
  const owl = { head: 0, headTo: 0, flare: 0, alert: 0, blink: 0 };

  function readColors() {
    const s = getComputedStyle(canvas);
    const v = (n, f) => (s.getPropertyValue(n).trim() || f);
    colors = { ink: v('--c-ink', '#8f9ab0'), dim: v('--c-dim', '#262c3a'), allow: v('--c-allow', '#52d394'),
               hit: v('--c-hit', '#ff4d5e'), signal: v('--c-signal', '#7a8dff'), body: v('--c-body', '#0a0c11') };
    mode = (window.rkMode && window.rkMode.get()) || 'enforce';
  }

  function resize() {
    const r = canvas.getBoundingClientRect();
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    W = Math.max(1, Math.floor(r.width));
    H = Math.max(1, Math.floor(r.height));
    canvas.width = W * dpr;
    canvas.height = H * dpr;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    line = Math.round(H * 0.5);
    u = Math.min(H * 0.34, W * 0.36, 190) / 100;
    // Lanes: each has its own pace, and launches its next call only once the
    // previous one has climbed clear, so labels never stack.
    lanes = [];
    const gap = W < 420 ? 72 : 88;
    for (let x = 118; x < W - 52; x += gap) {
      if (Math.abs(x - W / 2) > 50 * u) lanes.push({ x, v: 34 + Math.random() * 30, last: null });
    }
  }

  function spawn(lane, y) {
    const c = { x: lane.x, y: y === undefined ? H + 16 : y, v: lane.v, lane,
                text: CALLS[Math.floor(Math.random() * CALLS.length)],
                deny: Math.random() < 0.4, a: 0.55 + Math.random() * 0.4, state: 'rise' };
    lane.last = c;
    calls.push(c);
  }
  function feed() {
    for (const lane of lanes) {
      const l = lane.last;
      const clear = !l || l.dead || l.state !== 'rise' || l.y < H - 44 - Math.random() * 90;
      if (clear && Math.random() < 0.05) spawn(lane);
    }
  }

  function notice(x) {
    owl.headTo = Math.max(-0.38, Math.min(0.38, (x - W / 2) / (W * 0.9)));
    owl.alert = 1;
  }

  function cross(c) {
    if (!c.deny) { c.state = 'in'; return; }
    notice(c.x);
    document.dispatchEvent(new CustomEvent('rk:hit', { detail: { x: c.x / W, mode } }));
    if (mode === 'enforce') {
      c.state = 'back';
      c.v = -c.v * 1.1;
      c.side = c.x < W / 2 ? -1 : 1;
      owl.flare = 1;
      for (let i = 0; i < 8; i++) {
        const a = Math.PI + Math.random() * Math.PI;
        shards.push({ x: c.x, y: line, vx: Math.cos(a) * 50, vy: -Math.sin(a) * 50, life: 1 });
      }
      marks.push({ x: c.x, y: line + 16, life: 1, text: '-1 EPERM' });
    } else {
      c.state = 'audited';
      marks.push({ x: c.x, y: line - 16, life: 1, text: 'AUDIT · would deny' });
    }
  }

  function step(dt) {
    t += dt;
    feed();
    for (const c of calls) {
      c.y -= c.v * dt;
      if (c.state === 'back') c.x += c.side * 26 * dt;   // knocked back off the lane
      if (c.state === 'rise' && c.y <= line) cross(c);
      if (c.y < -20 || c.y > H + 40 || (c.state === 'back' && c.y > line + 72) ||
          ((c.state === 'in' || c.state === 'audited') && c.y < line - H * 0.36)) c.dead = true;
    }
    calls = calls.filter(c => !c.dead);
    for (const s of shards) { s.x += s.vx * dt; s.y += s.vy * dt; s.vy += 90 * dt; s.life -= dt * 1.5; }
    shards = shards.filter(s => s.life > 0);
    for (const m of marks) { m.life -= dt * 0.8; }
    marks = marks.filter(m => m.life > 0);

    owl.alert = Math.max(0, owl.alert - dt * 1.2);
    owl.flare = Math.max(0, owl.flare - dt * 2.2);
    if (mode === 'audit' && owl.alert < 0.2) owl.headTo = Math.sin(t * 0.7) * 0.28;   // scanning
    owl.head += (owl.headTo - owl.head) * Math.min(1, dt * 6);
    owl.blink = owl.blink > 0 ? owl.blink - dt : (Math.random() < dt * 0.25 ? 0.13 : 0);
  }

  /* ── The Warden ───────────────────────────────────────────────────── */
  function ellipse(cx, cy, rx, ry) { ctx.moveTo(cx + rx, cy); ctx.ellipse(cx, cy, rx, ry, 0, 0, Math.PI * 2); }

  function wing(fx, fy, side) {
    const f = owl.flare;
    ctx.beginPath();
    ctx.moveTo(fx + side * 26 * u, fy - 60 * u);
    ctx.quadraticCurveTo(fx + side * (40 + f * 34) * u, fy - (44 + f * 22) * u, fx + side * (36 + f * 40) * u, fy - (10 + f * 14) * u);
    ctx.lineTo(fx + side * 24 * u, fy - 8 * u);
    ctx.closePath();
    ctx.fill();
    ctx.stroke();
    // primary feathers
    ctx.beginPath();
    for (let i = 1; i <= 3; i++) {
      ctx.moveTo(fx + side * (28 + i * 2) * u, fy - (54 - i * 12) * u);
      ctx.lineTo(fx + side * (34 + f * 30 + i) * u, fy - (40 - i * 10 + f * 10) * u);
    }
    ctx.stroke();
  }

  function drawOwl() {
    const fx = W / 2, fy = line;
    const sig = owl.alert > 0.05 && mode === 'enforce' ? colors.hit : colors.signal;
    ctx.save();
    ctx.lineJoin = 'miter';
    ctx.lineWidth = Math.max(1.5, 1.6 * u);
    ctx.strokeStyle = sig;
    ctx.fillStyle = colors.body;
    ctx.shadowColor = sig;
    ctx.shadowBlur = 16 + owl.alert * 10;

    wing(fx, fy, -1);
    wing(fx, fy, 1);

    // Body
    ctx.beginPath(); ellipse(fx, fy - 40 * u, 27 * u, 40 * u); ctx.fill(); ctx.stroke();
    ctx.shadowBlur = 0;
    // Chest: engraved chevrons
    ctx.globalAlpha = 0.55;
    ctx.beginPath();
    for (let i = 0; i < 4; i++) {
      const y = fy - (44 - i * 8) * u, w = (14 - i * 2) * u;
      ctx.moveTo(fx - w, y); ctx.lineTo(fx, y + 4 * u); ctx.lineTo(fx + w, y);
    }
    ctx.stroke();
    ctx.globalAlpha = 1;
    // Feet on the boundary
    ctx.beginPath();
    for (const s of [-1, 1]) {
      const x = fx + s * 9 * u;
      ctx.moveTo(x - 4 * u, fy); ctx.lineTo(x, fy - 4 * u); ctx.lineTo(x + 4 * u, fy);
      ctx.moveTo(x, fy - 4 * u); ctx.lineTo(x, fy);
    }
    ctx.stroke();

    // Head, turned toward whatever it is watching
    ctx.translate(fx, fy - 70 * u);
    ctx.rotate(owl.head);
    ctx.shadowBlur = 14;
    ctx.beginPath();
    ctx.moveTo(-30 * u, -6 * u);
    ctx.lineTo(-26 * u, -30 * u);           // left tuft
    ctx.lineTo(-14 * u, -18 * u);
    ctx.quadraticCurveTo(0, -24 * u, 14 * u, -18 * u);
    ctx.lineTo(26 * u, -30 * u);            // right tuft
    ctx.lineTo(30 * u, -6 * u);
    ctx.quadraticCurveTo(30 * u, 18 * u, 0, 20 * u);
    ctx.quadraticCurveTo(-30 * u, 18 * u, -30 * u, -6 * u);
    ctx.closePath();
    ctx.fill(); ctx.stroke();
    ctx.shadowBlur = 0;

    // Facial discs and eyes
    for (const s of [-1, 1]) {
      const ex = s * 13 * u, ey = -3 * u;
      ctx.globalAlpha = 0.5;
      ctx.beginPath(); ctx.arc(ex, ey, 12 * u, 0, Math.PI * 2); ctx.stroke();
      ctx.globalAlpha = 1;
      ctx.shadowColor = sig;
      ctx.shadowBlur = 12;
      ctx.beginPath(); ctx.arc(ex, ey, 7.5 * u, 0, Math.PI * 2); ctx.stroke();
      ctx.shadowBlur = 0;
      if (owl.blink > 0) {
        ctx.beginPath(); ctx.moveTo(ex - 7 * u, ey); ctx.lineTo(ex + 7 * u, ey); ctx.stroke();
        continue;
      }
      const pr = (mode === 'enforce' ? 3.2 + owl.alert * 1.4 : 2.6) * u;
      ctx.fillStyle = sig;
      ctx.shadowColor = sig;
      ctx.shadowBlur = 10;
      ctx.beginPath(); ctx.arc(ex + owl.head * 6 * u, ey, pr, 0, Math.PI * 2); ctx.fill();
      ctx.shadowBlur = 0;
      if (mode === 'audit') {
        // Half-lidded and scanning
        ctx.fillStyle = colors.body;
        ctx.fillRect(ex - 8 * u, ey - 8 * u, 16 * u, 7.2 * u);
        ctx.beginPath(); ctx.moveTo(ex - 7.5 * u, ey - 0.8 * u); ctx.lineTo(ex + 7.5 * u, ey - 0.8 * u); ctx.stroke();
        const a = t * 2.4 * s;
        ctx.globalAlpha = 0.6;
        ctx.beginPath(); ctx.arc(ex, ey, 10 * u, a, a + 0.9); ctx.stroke();
        ctx.globalAlpha = 1;
      }
      ctx.fillStyle = colors.body;
    }
    // Beak
    ctx.beginPath(); ctx.moveTo(-3 * u, 6 * u); ctx.lineTo(0, 12 * u); ctx.lineTo(3 * u, 6 * u); ctx.stroke();
    ctx.restore();

  }

  function draw() {
    ctx.clearRect(0, 0, W, H);
    ctx.textAlign = 'left';
    ctx.textBaseline = 'middle';
    ctx.font = '500 10px "IBM Plex Mono", ui-monospace, monospace';
    ctx.fillStyle = colors.ink;
    ctx.globalAlpha = 0.55;
    ctx.fillText('KERNEL SPACE', 4, line - 14);
    ctx.fillText('USER SPACE', 4, line + 16);
    ctx.globalAlpha = 1;

    ctx.textAlign = 'center';
    ctx.font = '500 12px "IBM Plex Mono", ui-monospace, monospace';
    for (const c of calls) {
      let color = colors.ink, alpha = c.a;
      if (c.state === 'in') { color = colors.allow; alpha = c.a * Math.max(0, 1 - (line - c.y) / (H * 0.36)); }
      else if (c.state === 'audited') { color = colors.hit; alpha = c.a * Math.max(0, 1 - (line - c.y) / (H * 0.36)); }
      else if (c.state === 'back') { color = colors.hit; alpha = c.a * Math.max(0, 1 - (c.y - line) / 70); }
      ctx.globalAlpha = alpha;
      ctx.fillStyle = color;
      ctx.fillText(c.text, c.x, c.y);
      if (c.state === 'rise') {
        ctx.globalAlpha = c.a * 0.35;
        ctx.fillStyle = colors.dim;
        ctx.fillRect(c.x - 0.5, c.y + 12, 1, 28);
      }
    }
    ctx.globalAlpha = 1;

    // The boundary
    const g = ctx.createLinearGradient(0, 0, W, 0);
    g.addColorStop(0, 'rgba(0,0,0,0)');
    g.addColorStop(0.12, colors.signal);
    g.addColorStop(0.88, colors.signal);
    g.addColorStop(1, 'rgba(0,0,0,0)');
    ctx.shadowColor = colors.signal;
    ctx.shadowBlur = 16;
    ctx.fillStyle = g;
    ctx.fillRect(0, line - 1, W, 2);
    ctx.shadowBlur = 0;

    if (!document.documentElement.classList.contains('owl-3d')) drawOwl();

    for (const s of shards) { ctx.globalAlpha = Math.max(0, s.life); ctx.fillStyle = colors.hit; ctx.fillRect(s.x - 1.5, s.y - 1.5, 3, 3); }
    ctx.font = '600 11px "IBM Plex Mono", ui-monospace, monospace';
    for (const m of marks) { ctx.globalAlpha = Math.max(0, m.life); ctx.fillStyle = colors.hit; ctx.fillText(m.text, m.x, m.y); }
    ctx.globalAlpha = 1;
  }

  function frame(now) {
    if (!running) return;
    const dt = Math.min(0.05, (now - last) / 1000 || 0);
    last = now;
    step(dt);
    draw();
    requestAnimationFrame(frame);
  }

  function still() {
    calls = []; shards = []; marks = [];
    for (const lane of lanes) spawn(lane, line + 30 + Math.random() * (H - line - 40));
    marks.push({ x: (lanes[lanes.length - 1] || { x: W * 0.8 }).x, y: mode === 'enforce' ? line + 16 : line - 16, life: 0.9,
                 text: mode === 'enforce' ? '-1 EPERM' : 'AUDIT · would deny' });
    draw();
  }

  function start() {
    if (running || reduced.matches || !visible || document.hidden) return;
    running = true;
    last = performance.now();
    requestAnimationFrame(frame);
  }
  function stop() { running = false; }

  function init() {
    readColors();
    resize();
    if (reduced.matches) { still(); return; }
    for (const lane of lanes) spawn(lane, line + 30 + Math.random() * (H - line - 40));
    draw();
    start();
  }

  /* ── Boot sequence beside the heading ───────────────────────────── */
  function boot() {
    const pre = document.querySelector('.boot');
    if (!pre) return;
    const syncMode = () => pre.querySelectorAll('.boot-mode').forEach(n => { n.textContent = window.rkMode ? window.rkMode.get() : mode; });
    document.addEventListener('rk:mode', () => { readColors(); syncMode(); });
    syncMode();
    if (reduced.matches) return;   // the finished lines are already in the page
    const lines = Array.from(pre.querySelectorAll('span'));
    const html = lines.map(l => l.innerHTML);
    const text = lines.map(l => l.textContent);
    lines.forEach(l => { l.textContent = ''; });
    let li = 0, ci = 0;
    (function type() {
      if (li >= lines.length) return;
      const l = lines[li];
      l.classList.add('typing');
      ci = Math.min(text[li].length, ci + 2);
      l.textContent = text[li].slice(0, ci);
      if (ci >= text[li].length) {
        l.innerHTML = html[li];
        l.classList.remove('typing');
        syncMode();
        li++; ci = 0;
        setTimeout(type, 260);
      } else {
        setTimeout(type, 28);
      }
    })();
  }
  boot();

  canvas.addEventListener('click', () => window.rkMode && window.rkMode.toggle());
  document.addEventListener('rk:mode', () => {
    readColors();
    owl.alert = 0.6; owl.flare = mode === 'enforce' ? 0.8 : 0;
    if (!running) still();
  });
  window.addEventListener('resize', () => { resize(); if (!running) still(); });
  document.addEventListener('visibilitychange', () => (document.hidden ? stop() : start()));
  reduced.addEventListener('change', () => { stop(); init(); });
  if ('IntersectionObserver' in window) {
    new IntersectionObserver(entries => { visible = entries[0].isIntersecting; visible ? start() : stop(); }).observe(canvas);
  }
  init();
  // Redraw once the mono face has loaded, so the labels render in it.
  if (document.fonts && document.fonts.ready) document.fonts.ready.then(() => { if (!running) draw(); });
})();
