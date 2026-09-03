/* Reality Kernel — Causal Trajectory Hero Animation
   Cinematic canvas viz: a center bifurcation point, particles streaming
   into 5 shadow worlds, some converging green (Basin A), some terminating
   red (Basin B). Phosphor cryptographic feel. */
(function () {
  const COLORS = {
    line: 'rgba(110, 231, 183, 0.18)',
    line2: 'rgba(255, 255, 255, 0.06)',
    ok: 'rgba(110, 231, 183, 1)',
    warn: 'rgba(255, 183, 42, 1)',
    block: 'rgba(255, 58, 77, 1)',
    text: 'rgba(244, 244, 246, 0.8)',
    faint: 'rgba(255, 255, 255, 0.12)',
  };

  function init(canvas) {
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    let DPR = Math.min(window.devicePixelRatio || 1, 2);
    let W = 0, H = 0, CX = 0, CY = 0;

    function resize() {
      const rect = canvas.getBoundingClientRect();
      W = rect.width; H = rect.height;
      canvas.width = W * DPR; canvas.height = H * DPR;
      ctx.setTransform(DPR, 0, 0, DPR, 0, 0);
      CX = W / 2; CY = H / 2;
    }
    resize();
    window.addEventListener('resize', resize);

    const NUM_WORLDS = 5;
    const RADIUS = () => Math.min(W, H) * 0.40;

    // Each world has an angle around the center
    const worlds = [];
    for (let i = 0; i < NUM_WORLDS; i++) {
      const a = (i / NUM_WORLDS) * Math.PI * 2 - Math.PI / 2;
      // 1 = ok (basin A), 2 = warn, 3 = block (basin B)
      const r = Math.random();
      worlds.push({
        angle: a,
        type: r < 0.55 ? 'ok' : r < 0.8 ? 'warn' : 'block',
        seed: Math.random() * 1000,
      });
    }

    const particles = [];
    function spawnParticle() {
      const w = worlds[Math.floor(Math.random() * worlds.length)];
      particles.push({
        world: w,
        t: 0,                       // 0 → 1 progress
        speed: 0.003 + Math.random() * 0.004,
        size: 1.5 + Math.random() * 1.3,
        spread: (Math.random() - 0.5) * 0.18, // angle wobble
      });
    }

    // Spawn schedule
    let spawnAcc = 0;
    function tick(dt) {
      spawnAcc += dt;
      while (spawnAcc > 60) { spawnAcc -= 60; spawnParticle(); }
      for (let i = particles.length - 1; i >= 0; i--) {
        const p = particles[i];
        p.t += p.speed * (dt / 16);
        if (p.t >= 1) particles.splice(i, 1);
      }
    }

    function draw(time) {
      ctx.clearRect(0, 0, W, H);

      const R = RADIUS();

      // Outer rings (concentric phase-space rings)
      ctx.strokeStyle = COLORS.faint;
      ctx.lineWidth = 1;
      for (let r = R * 1.04; r > 8; r -= R * 0.18) {
        ctx.beginPath();
        ctx.arc(CX, CY, r, 0, Math.PI * 2);
        ctx.stroke();
      }

      // Radial spokes to each world
      worlds.forEach(w => {
        const tx = CX + Math.cos(w.angle) * R;
        const ty = CY + Math.sin(w.angle) * R;
        ctx.strokeStyle = w.type === 'block' ? 'rgba(255,58,77,0.18)' : w.type === 'warn' ? 'rgba(255,183,42,0.16)' : COLORS.line;
        ctx.lineWidth = 1;
        ctx.beginPath(); ctx.moveTo(CX, CY); ctx.lineTo(tx, ty); ctx.stroke();
      });

      // Particles travelling along trajectories with slight curve
      particles.forEach(p => {
        const w = p.world;
        const baseAngle = w.angle + p.spread * Math.sin(time * 0.001 + w.seed);
        const r = p.t * R;
        const px = CX + Math.cos(baseAngle) * r;
        const py = CY + Math.sin(baseAngle) * r;
        const color = w.type === 'block' ? COLORS.block : w.type === 'warn' ? COLORS.warn : COLORS.ok;

        // Trail
        const tailLen = 22;
        for (let k = 0; k < tailLen; k++) {
          const tt = Math.max(0, p.t - k * 0.012);
          const rr = tt * R;
          const tx = CX + Math.cos(baseAngle) * rr;
          const ty = CY + Math.sin(baseAngle) * rr;
          const alpha = (1 - k / tailLen) * 0.65;
          ctx.fillStyle = color.replace('1)', alpha + ')');
          ctx.beginPath(); ctx.arc(tx, ty, p.size * (1 - k / tailLen * 0.8), 0, Math.PI * 2); ctx.fill();
        }
        // Head
        ctx.fillStyle = color;
        ctx.shadowBlur = 14; ctx.shadowColor = color;
        ctx.beginPath(); ctx.arc(px, py, p.size + 0.8, 0, Math.PI * 2); ctx.fill();
        ctx.shadowBlur = 0;
      });

      // Terminal nodes (worlds)
      worlds.forEach((w, i) => {
        const tx = CX + Math.cos(w.angle) * R;
        const ty = CY + Math.sin(w.angle) * R;
        const color = w.type === 'block' ? COLORS.block : w.type === 'warn' ? COLORS.warn : COLORS.ok;
        const pulse = 0.7 + 0.3 * Math.sin(time * 0.002 + i);
        ctx.shadowBlur = 18; ctx.shadowColor = color;
        ctx.fillStyle = color;
        ctx.beginPath(); ctx.arc(tx, ty, 3 + pulse, 0, Math.PI * 2); ctx.fill();
        ctx.shadowBlur = 0;
        // Outer ring
        ctx.strokeStyle = color.replace('1)', '0.35)');
        ctx.lineWidth = 1;
        ctx.beginPath(); ctx.arc(tx, ty, 10 + pulse * 2, 0, Math.PI * 2); ctx.stroke();
        // World label
        ctx.fillStyle = 'rgba(255,255,255,0.45)';
        ctx.font = '9px JetBrains Mono, monospace';
        const lx = CX + Math.cos(w.angle) * (R + 18);
        const ly = CY + Math.sin(w.angle) * (R + 18);
        ctx.textAlign = 'center'; ctx.textBaseline = 'middle';
        ctx.fillText('W' + String(i + 1).padStart(2, '0'), lx, ly);
      });

      // Center kernel node
      ctx.shadowBlur = 24; ctx.shadowColor = 'rgba(110,231,183,0.5)';
      ctx.fillStyle = 'rgba(244,244,246,1)';
      ctx.beginPath(); ctx.arc(CX, CY, 5, 0, Math.PI * 2); ctx.fill();
      ctx.shadowBlur = 0;
      ctx.strokeStyle = 'rgba(110,231,183,0.5)';
      ctx.lineWidth = 1;
      ctx.beginPath(); ctx.arc(CX, CY, 14 + Math.sin(time * 0.003) * 2, 0, Math.PI * 2); ctx.stroke();
      ctx.strokeStyle = 'rgba(110,231,183,0.2)';
      ctx.beginPath(); ctx.arc(CX, CY, 24, 0, Math.PI * 2); ctx.stroke();

      // Center label
      ctx.fillStyle = 'rgba(110,231,183,0.85)';
      ctx.font = '500 9px JetBrains Mono, monospace';
      ctx.textAlign = 'center'; ctx.textBaseline = 'middle';
      ctx.fillText('KERNEL', CX, CY + 38);

      // Separatrix arc — basin boundary
      ctx.strokeStyle = 'rgba(255, 58, 77, 0.22)';
      ctx.setLineDash([4, 6]);
      ctx.lineWidth = 1.2;
      ctx.beginPath(); ctx.arc(CX, CY, R * 0.72, 0, Math.PI * 2); ctx.stroke();
      ctx.setLineDash([]);
    }

    let last = performance.now();
    function loop(now) {
      const dt = Math.min(now - last, 60);
      last = now;
      tick(dt);
      draw(now);
      requestAnimationFrame(loop);
    }
    requestAnimationFrame(loop);
  }

  window.RKCausal = { init };
})();
