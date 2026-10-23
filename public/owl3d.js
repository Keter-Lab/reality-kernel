/* The Warden in light: Reality Kernel's guardian owl as a field of a few
   thousand glowing points, drawn with raw WebGL (no library).
   - It turns gently toward the pointer and breathes.
   - enforce: where a call is denied, its particles flare red and its wings open.
   - audit: an amber band scans through it and its eyes half close.
   - Scrolling down dissolves it into a stream that pours into the audit tape
     below; scrolling back up reassembles it.
   Without WebGL the 2D owl in hero.js is drawn instead. Decorative only. */
(function () {
  const canvas = document.getElementById('owl-canvas');
  if (!canvas) return;
  const gl = canvas.getContext('webgl', { alpha: true, premultipliedAlpha: true, antialias: false });
  if (!gl) return;
  document.documentElement.classList.add('owl-3d');
  const reduced = window.matchMedia('(prefers-reduced-motion: reduce)');

  /* ── The owl as points (owl units: feet at y 0, tufts near y 1) ───── */
  const pos = [], stream = [], seed = [], kind = [];
  // kind: 0 body fill, 1 outline, 2 eye, 3 upper eye (lidded in audit), 4 wing, 5 chest
  function add(x, y, z, k) {
    pos.push(x, y, z);
    const s = Math.random();
    seed.push(s);
    kind.push(k);
    stream.push((Math.random() - 0.5) * 2.6, -0.25 - Math.random() * 1.1, (Math.random() - 0.5) * 0.6);
  }
  function ring(cx, cy, r, n, z, k, topKind) {
    for (let i = 0; i < n; i++) {
      const a = (i / n) * Math.PI * 2, y = cy + Math.sin(a) * r;
      add(cx + Math.cos(a) * r, y, z, topKind !== undefined && Math.sin(a) > 0.05 ? topKind : k);
    }
  }
  function ellipseOutline(cx, cy, rx, ry, n, z) {
    for (let i = 0; i < n; i++) { const a = (i / n) * Math.PI * 2; add(cx + Math.cos(a) * rx, cy + Math.sin(a) * ry, z, 1); }
  }
  function ellipsoid(cx, cy, rx, ry, n, depth, k) {
    for (let i = 0; i < n; i++) {
      const a = Math.random() * Math.PI * 2, r = Math.sqrt(Math.random());
      const x = Math.cos(a) * r, y = Math.sin(a) * r;
      const zf = Math.sqrt(Math.max(0, 1 - r * r)) * depth;
      add(cx + x * rx, cy + y * ry, Math.random() < 0.75 ? zf : -zf, k);
    }
  }
  function segment(x0, y0, x1, y1, n, z, k) {
    for (let i = 0; i <= n; i++) { const t = i / n; add(x0 + (x1 - x0) * t, y0 + (y1 - y0) * t, z, k); }
  }
  function curve(pts, n, z, k) {   // quadratic through three points
    const [a, b, c] = pts;
    for (let i = 0; i <= n; i++) {
      const t = i / n, u = 1 - t;
      add(u * u * a[0] + 2 * u * t * b[0] + t * t * c[0], u * u * a[1] + 2 * u * t * b[1] + t * t * c[1], z, k);
    }
  }
  // Body and head
  ellipsoid(0, 0.40, 0.27, 0.40, 1000, 0.22, 0);
  // Scalloped feather rows down the breast
  for (let row = 0; row < 7; row++) {
    const y = 0.52 - row * 0.065, half = Math.sqrt(Math.max(0, 1 - Math.pow((y - 0.40) / 0.40, 2))) * 0.24;
    const n = Math.max(2, Math.round(half / 0.045));
    for (let i = 0; i < n; i++) {
      const cx = -half + (i + 0.5 + (row % 2) * 0.5) * (2 * half / (n + 0.5));
      if (Math.abs(cx) > half) continue;
      for (let k = 0; k <= 10; k++) {
        const a = Math.PI + (k / 10) * Math.PI;
        add(cx + Math.cos(a) * 0.026, y + Math.sin(a) * 0.022, 0.2, 5);
      }
    }
  }
  ellipseOutline(0, 0.40, 0.27, 0.40, 260, 0.02);
  ellipsoid(0, 0.71, 0.30, 0.21, 1000, 0.20, 0);
  ellipseOutline(0, 0.71, 0.30, 0.21, 220, 0.05);
  for (const s of [-1, 1]) {
    // Ear tufts
    segment(s * 0.29, 0.77, s * 0.27, 1.0, 34, 0.04, 1);
    segment(s * 0.27, 1.0, s * 0.13, 0.88, 34, 0.04, 1);
    // Facial disc with feather rays, iris rings, pupil and a glint
    ring(s * 0.13, 0.73, 0.12, 96, 0.17, 1);
    for (let r = 0; r < 14; r++) {
      const a = (r / 14) * Math.PI * 2;
      for (let k = 0; k <= 6; k++) {
        const d = 0.085 + (k / 6) * 0.03;
        add(s * 0.13 + Math.cos(a) * d, 0.73 + Math.sin(a) * d, 0.18, 5);
      }
    }
    ring(s * 0.13, 0.73, 0.075, 80, 0.21, 2, 3);
    ring(s * 0.13, 0.73, 0.056, 60, 0.215, 2, 3);
    ring(s * 0.13, 0.73, 0.04, 44, 0.22, 2, 3);
    ellipsoid(s * 0.13, 0.73, 0.028, 0.028, 60, 0.02, 2);
    ellipsoid(s * 0.13 - 0.018, 0.748, 0.008, 0.008, 18, 0.03, 6);
    // Brow: a sharp V meeting above the beak
    segment(s * 0.25, 0.83, s * 0.02, 0.77, 30, 0.22, 1);
    // Wings, behind the body
    curve([[s * 0.25, 0.62], [s * 0.42, 0.42], [s * 0.35, 0.10]], 90, -0.06, 4);
    segment(s * 0.35, 0.10, s * 0.23, 0.08, 24, -0.06, 4);
    ellipsoid(s * 0.31, 0.36, 0.07, 0.22, 380, 0.05, 4);
    for (let i = 1; i <= 3; i++) segment(s * (0.29 + i * 0.015), 0.56 - i * 0.12, s * (0.37 + i * 0.01), 0.42 - i * 0.10, 16, -0.04, 4);
    // Feet on the boundary
    segment(s * 0.13, 0.0, s * 0.09, 0.05, 10, 0.08, 1);
    segment(s * 0.05, 0.0, s * 0.09, 0.05, 10, 0.08, 1);
  }
  // Beak and chest chevrons
  segment(-0.03, 0.66, 0, 0.60, 12, 0.24, 1);
  segment(0.03, 0.66, 0, 0.60, 12, 0.24, 1);
  for (let i = 0; i < 4; i++) {
    const y = 0.46 - i * 0.08, w = 0.14 - i * 0.02;
    segment(-w, y, 0, y - 0.04, 22, 0.24, 5);
    segment(0, y - 0.04, w, y, 22, 0.24, 5);
  }
  const COUNT = seed.length;

  /* ── Shaders ──────────────────────────────────────────────────────── */
  const VS = `
    attribute vec3 aPos; attribute vec3 aStream; attribute float aSeed; attribute float aKind;
    uniform float uTime, uScroll, uAspect, uScale, uDpr, uAudit, uFlare, uScan, uIntro;
    uniform vec2 uRot, uHit;
    uniform vec3 uSig, uHitCol;
    varying vec3 vCol; varying float vA;
    void main() {
      vec3 p = aPos;
      // wings open on a strike
      if (aKind > 3.5 && aKind < 4.5) p.x += sign(p.x) * uFlare * 0.16 * (0.7 - p.y * 0.4);
      // breathing and a faint shimmer
      p.xy = vec2(p.x, p.y - 0.45) * (1.0 + sin(uTime * 1.4) * 0.008) + vec2(0.0, 0.45);
      p += 0.004 * vec3(sin(uTime * 2.0 + aSeed * 40.0), cos(uTime * 1.7 + aSeed * 30.0), 0.0);
      // turn toward the pointer, around the owl's centre
      p.y -= 0.45;
      float cy = cos(uRot.x), sy = sin(uRot.x);
      p = vec3(p.x * cy + p.z * sy, p.y, -p.x * sy + p.z * cy);
      float cx = cos(uRot.y), sx = sin(uRot.y);
      p = vec3(p.x, p.y * cx - p.z * sx, p.y * sx + p.z * cx);
      p.y += 0.45;
      // dissolve into the stream as the page scrolls
      float d = clamp(uScroll * 1.6 - aSeed * 0.6, 0.0, 1.0);
      d = max(d, clamp(1.0 - (uIntro * 1.7 - aSeed * 0.7), 0.0, 1.0));
      d = d * d * (3.0 - 2.0 * d);
      vec3 s = aStream + vec3(sin(uTime * 0.8 + aSeed * 12.0) * 0.05, -uTime * 0.0, 0.0);
      p = mix(p, s, d);
      float persp = 2.8 / (2.8 - p.z);
      gl_Position = vec4(p.x * persp * uScale / uAspect, p.y * persp * uScale, 0.0, 1.0);
      float big = ((aKind > 0.5 && aKind < 3.5) || aKind > 5.5) ? 1.0 : 0.0;
      gl_PointSize = (2.1 + big * 1.5) * uDpr * persp * (0.85 + 0.3 * fract(aSeed * 91.7 + uTime * 0.3));
      // colour: the mode's signal; red where a denial struck; a scanning band in audit
      vec3 col = uSig;
      float hit = uFlare * smoothstep(0.32, 0.0, distance(aPos.xy, uHit));
      col = mix(col, uHitCol, clamp(hit * 1.6, 0.0, 1.0));
      float band = uAudit * smoothstep(0.06, 0.0, abs(aPos.y - uScan));
      col += band * 0.6;
      float a = aKind < 0.5 ? 0.62 : 1.0;
      if (aKind > 1.5 && aKind < 3.5) a = 1.0;
      if (aKind > 2.5 && aKind < 3.5) a = mix(1.0, 0.1, uAudit);
      if (aKind > 4.5) a = 0.8;
      if (aKind > 5.5) { a = 1.0; col = mix(col, vec3(1.0), 0.75 * (1.0 - uAudit)); }
      if (aKind > 3.5 && aKind < 4.5) a = 0.72;
      vCol = col;
      vA = a * (1.0 - d * 0.55);
    }`;
  const FS = `
    precision mediump float;
    varying vec3 vCol; varying float vA;
    void main() {
      float r = length(gl_PointCoord - 0.5);
      float a = smoothstep(0.5, 0.0, r) * vA;
      gl_FragColor = vec4(vCol * a, a);
    }`;
  function shader(type, src) {
    const s = gl.createShader(type);
    gl.shaderSource(s, src);
    gl.compileShader(s);
    if (!gl.getShaderParameter(s, gl.COMPILE_STATUS)) throw new Error(gl.getShaderInfoLog(s));
    return s;
  }
  let prog;
  try {
    prog = gl.createProgram();
    gl.attachShader(prog, shader(gl.VERTEX_SHADER, VS));
    gl.attachShader(prog, shader(gl.FRAGMENT_SHADER, FS));
    gl.linkProgram(prog);
    if (!gl.getProgramParameter(prog, gl.LINK_STATUS)) throw new Error(gl.getProgramInfoLog(prog));
  } catch (e) {
    document.documentElement.classList.remove('owl-3d');   // fall back to the 2D owl
    return;
  }
  gl.useProgram(prog);
  function buffer(name, data, size) {
    const b = gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, b);
    gl.bufferData(gl.ARRAY_BUFFER, new Float32Array(data), gl.STATIC_DRAW);
    const loc = gl.getAttribLocation(prog, name);
    gl.enableVertexAttribArray(loc);
    gl.vertexAttribPointer(loc, size, gl.FLOAT, false, 0, 0);
  }
  buffer('aPos', pos, 3);
  buffer('aStream', stream, 3);
  buffer('aSeed', seed, 1);
  buffer('aKind', kind, 1);
  const U = {};
  for (const n of ['uIntro', 'uTime', 'uScroll', 'uAspect', 'uScale', 'uDpr', 'uAudit', 'uFlare', 'uScan', 'uRot', 'uHit', 'uSig', 'uHitCol']) U[n] = gl.getUniformLocation(prog, n);
  gl.enable(gl.BLEND);
  gl.blendFunc(gl.ONE, gl.ONE);   // additive: overlapping points glow
  gl.clearColor(0, 0, 0, 0);

  /* ── State ────────────────────────────────────────────────────────── */
  let dpr = 1, aspect = 1, scale = 0.8, running = false, visible = true, t0 = performance.now();
  let rot = [0, 0], rotTo = [0, 0], flare = 0, hit = [0, 0.5], scroll = 0, lastCharge = -1;
  let sig = [0.48, 0.55, 1.0], hitCol = [1.0, 0.3, 0.37], audit = 0, auditTo = 0;

  function rgb(css, fallback) {
    const m = css.match(/#([0-9a-f]{6})/i);
    if (!m) return fallback;
    const n = parseInt(m[1], 16);
    return [((n >> 16) & 255) / 255, ((n >> 8) & 255) / 255, (n & 255) / 255];
  }
  function readMode() {
    const s = getComputedStyle(canvas);
    sig = rgb(s.getPropertyValue('--c-signal'), sig);
    hitCol = rgb(s.getPropertyValue('--c-hit-red'), hitCol);
    auditTo = window.rkMode && window.rkMode.get() === 'audit' ? 1 : 0;
  }

  function resize() {
    const r = canvas.getBoundingClientRect();
    dpr = Math.min(window.devicePixelRatio || 1, 2);
    canvas.width = Math.max(1, Math.floor(r.width * dpr));
    canvas.height = Math.max(1, Math.floor(r.height * dpr));
    gl.viewport(0, 0, canvas.width, canvas.height);
    aspect = r.width / Math.max(1, r.height);
    scale = Math.min(0.82, 0.62 * aspect + 0.18);   // owl ~40% of the height, narrower boxes shrink it
  }

  const hero = canvas.closest('section');
  function readScroll() {
    if (!hero) return 0;
    const r = hero.getBoundingClientRect();
    return Math.max(0, Math.min(1, -r.top / (r.height * 0.75)));
  }

  function render(now) {
    const t = (now - t0) / 1000;
    audit += (auditTo - audit) * 0.06;
    flare *= 0.94;
    rot[0] += (rotTo[0] - rot[0]) * 0.06;
    rot[1] += (rotTo[1] - rot[1]) * 0.06;
    scroll += (readScroll() - scroll) * 0.12;
    // The tape below lights up as the Warden pours into it.
    const charge = Math.round(Math.min(1, scroll * 1.8) * 100) / 100;
    if (charge !== lastCharge) { document.documentElement.style.setProperty('--dissolve', String(charge)); lastCharge = charge; }
    gl.clear(gl.COLOR_BUFFER_BIT);
    gl.uniform1f(U.uIntro, reduced.matches ? 1 : Math.min(1, t / 2.2));
    gl.uniform1f(U.uTime, t);
    gl.uniform1f(U.uScroll, scroll);
    gl.uniform1f(U.uAspect, aspect);
    gl.uniform1f(U.uScale, scale);
    gl.uniform1f(U.uDpr, dpr);
    gl.uniform1f(U.uAudit, audit);
    gl.uniform1f(U.uFlare, flare);
    gl.uniform1f(U.uScan, 0.05 + ((t * 0.35) % 1.05));
    gl.uniform2f(U.uRot, rot[0], rot[1]);
    gl.uniform2f(U.uHit, hit[0], hit[1]);
    gl.uniform3f(U.uSig, sig[0], sig[1], sig[2]);
    gl.uniform3f(U.uHitCol, hitCol[0], hitCol[1], hitCol[2]);
    gl.drawArrays(gl.POINTS, 0, COUNT);
  }
  function loop(now) {
    if (!running) return;
    render(now);
    requestAnimationFrame(loop);
  }
  function start() {
    if (running || reduced.matches || !visible || document.hidden) return;
    running = true;
    requestAnimationFrame(loop);
  }
  function stop() { running = false; }

  /* ── Wiring ───────────────────────────────────────────────────────── */
  addEventListener('pointermove', e => {
    const r = canvas.getBoundingClientRect();
    const nx = (e.clientX - (r.left + r.width / 2)) / innerWidth;
    const ny = (e.clientY - (r.top + r.height / 2)) / innerHeight;
    rotTo = [Math.max(-0.5, Math.min(0.5, nx * 1.1)), Math.max(-0.25, Math.min(0.25, ny * 0.6))];
  }, { passive: true });
  // hero.js reports where a denied call met the boundary (x as a fraction of the width).
  document.addEventListener('rk:hit', e => {
    if (!e.detail || e.detail.mode !== 'enforce') return;
    const ox = ((e.detail.x - 0.5) * 2 * aspect) / scale;   // canvas x → owl units
    hit = [Math.max(-0.45, Math.min(0.45, ox)), 0.32];
    flare = 1;
    rotTo[0] = Math.max(-0.5, Math.min(0.5, ox * 0.6));
  });
  document.addEventListener('rk:mode', () => { readMode(); if (!running) render(performance.now()); });
  addEventListener('resize', () => { resize(); if (!running) render(performance.now()); });
  addEventListener('scroll', () => { if (!running) { scroll = readScroll(); render(performance.now()); } }, { passive: true });
  document.addEventListener('visibilitychange', () => (document.hidden ? stop() : start()));
  if ('IntersectionObserver' in window) {
    new IntersectionObserver(es => { visible = es[0].isIntersecting; visible ? start() : stop(); }).observe(canvas);
  }
  readMode();
  audit = auditTo;
  resize();
  render(performance.now());
  start();
})();
