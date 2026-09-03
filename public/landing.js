/* Reality Kernel · Dual-Threat Interactive Sandbox */
(function () {
  'use strict';

  const root = document.getElementById('threat-sandbox');
  if (!root) return;

  const el = {
    buttons: Array.from(root.querySelectorAll('[data-threat]')),
    state: document.getElementById('ts-console-state'),
    output: document.getElementById('ts-console-output'),
    injected: document.getElementById('ts-injected-command'),
    agent: document.getElementById('ts-agent-node'),
    shield: document.getElementById('ts-shield'),
    verdict: document.getElementById('ts-verdict'),
    attacker: document.getElementById('ts-attacker-box'),
    traceSafe: document.getElementById('ts-trace-safe'),
    traceAgent: document.getElementById('ts-trace-agent'),
    traceAttack: document.getElementById('ts-trace-attack'),
  };

  const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const wait = (ms) => new Promise((resolve) => setTimeout(resolve, reduced ? 40 : ms));

  function resetVisuals() {
    el.traceSafe.classList.remove('run', 'shattered');
    el.traceAgent.classList.remove('run', 'shattered');
    el.traceAttack.classList.remove('run', 'shattered');
    el.attacker.classList.remove('opacity-100');
    el.attacker.classList.add('opacity-0');
    el.injected.classList.add('opacity-0');
    el.shield.className = 'absolute left-[71%] top-1/2 -translate-y-1/2 rounded-xl border border-slate-300/80 bg-white/95 px-3 py-1.5 font-mono text-[10px] tracking-[0.16em] text-slate-500 transition-all duration-200';
    el.agent.className = 'relative z-10 flex flex-col items-center gap-3 transition-all duration-200';
  }

  function renderConsole(lines) {
    el.output.innerHTML = '';
    lines.forEach((line) => {
      const p = document.createElement('p');
      p.className = 'terminal-line' + (line.tone ? ' ' + line.tone : '');
      p.textContent = line.text;
      el.output.appendChild(p);
    });
    el.output.appendChild(el.injected);
  }

  function setVerdict(text, mode) {
    const cls = mode === 'allow'
      ? 'absolute left-1/2 bottom-5 -translate-x-1/2 inline-flex items-center rounded-lg border border-emerald-200 bg-emerald-50 px-3 py-1.5 font-mono text-[10px] sm:text-[11px] font-semibold tracking-wide text-emerald-700 whitespace-nowrap'
      : mode === 'block-red'
        ? 'absolute left-1/2 bottom-5 -translate-x-1/2 inline-flex items-center rounded-lg border border-red-200 bg-red-50 px-3 py-1.5 font-mono text-[10px] sm:text-[11px] font-semibold tracking-wide text-red-600 whitespace-nowrap'
        : 'absolute left-1/2 bottom-5 -translate-x-1/2 inline-flex items-center rounded-lg border border-orange-200 bg-orange-50 px-3 py-1.5 font-mono text-[10px] sm:text-[11px] font-semibold tracking-wide text-orange-600 whitespace-nowrap';
    el.verdict.className = cls;
    el.verdict.textContent = text;
  }

  async function runSafeScenario() {
    resetVisuals();
    el.state.textContent = 'Baseline execution';
    renderConsole([
      { text: '$ intent: fetch weather data for New York' },
      { text: '$ command: cat ./cache/weather.json' },
      { text: '[RK] world simulation consensus 5/5', tone: '' },
      { text: '[RK] syscall stream clean', tone: '' },
    ]);

    el.traceSafe.classList.add('run');
    await wait(450);
    el.shield.classList.add('border-emerald-300', 'bg-emerald-50', 'text-emerald-700');
    setVerdict('[ VERDICT: ALLOW ]', 'allow');
  }

  async function runRogueScenario() {
    resetVisuals();
    el.state.textContent = 'Internal anomaly detection';
    renderConsole([
      { text: '$ intent: fetch weather data for New York' },
      { text: '$ command: cat ./cache/weather.json' },
      { text: '[AGENT ERR]: recursive os.walk(/etc/) triggered', tone: 'error' },
      { text: '[RK] anomaly score elevated: 0.97', tone: 'error' },
    ]);

    el.agent.classList.add('scale-[1.03]', '[&_span]:!bg-orange-500');
    el.traceAgent.classList.add('run');
    await wait(430);
    el.shield.classList.add('border-orange-300', 'bg-orange-50', 'text-orange-700', 'scale-105');
    el.traceAgent.classList.add('shattered');
    await wait(160);
    el.traceAgent.classList.remove('run');
    setVerdict('[ VERDICT: BLOCK • ORIGIN: AGENT ANOMALY ]', 'block-orange');
  }

  async function runInjectionScenario() {
    resetVisuals();
    el.state.textContent = 'External payload interception';
    renderConsole([
      { text: '$ intent: fetch weather data for New York' },
      { text: '$ input channel: external payload vector', tone: 'attack' },
      { text: '[RK] foreign instruction detected', tone: 'attack' },
      { text: '[RK] coercion attempt blocked', tone: 'attack' },
    ]);

    el.attacker.classList.remove('opacity-0');
    el.attacker.classList.add('opacity-100');
    await wait(100);
    el.traceAttack.classList.add('run');
    await wait(310);
    el.injected.classList.remove('opacity-0');
    await wait(140);
    el.traceAgent.classList.add('run');
    await wait(280);
    el.shield.classList.add('border-red-300', 'bg-red-50', 'text-red-700', 'scale-105');
    el.traceAttack.classList.add('shattered');
    el.traceAgent.classList.add('shattered');
    await wait(180);
    el.traceAttack.classList.remove('run');
    el.traceAgent.classList.remove('run');
    setVerdict('[ VERDICT: BLOCK • ORIGIN: EXTERNAL EXPLOIT • TIME: 0.31ms ]', 'block-red');
  }

  async function runScenario(type) {
    el.buttons.forEach((btn) => {
      btn.classList.toggle('is-active', btn.dataset.threat === type);
      btn.disabled = true;
    });

    if (type === 'safe') await runSafeScenario();
    if (type === 'rogue') await runRogueScenario();
    if (type === 'injection') await runInjectionScenario();

    el.buttons.forEach((btn) => { btn.disabled = false; });
  }

  el.buttons.forEach((btn) => {
    btn.addEventListener('click', () => runScenario(btn.dataset.threat));
  });

  runScenario('safe');
})();
