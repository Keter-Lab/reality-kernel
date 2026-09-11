import re

# 1. Update index.html with Founder Note
with open('public/index.html', 'r', encoding='utf-8') as f:
    index = f.read()

founder_section = '''
  <section class="py-24 bg-slate-50 border-t border-slate-200">
    <div class="mx-auto max-w-4xl px-5 sm:px-8">
      <div class="flex flex-col md:flex-row items-center md:items-start gap-8 md:gap-12">
        <div class="shrink-0 relative">
          <div class="absolute inset-0 bg-gradient-to-tr from-emerald-400/20 to-sky-400/20 rounded-full blur-xl"></div>
          <img src="/founder.jpg" alt="Tabrez Mukadam" class="relative w-32 h-32 md:w-40 md:h-40 rounded-full object-cover shadow-lg border border-slate-200/60" />
        </div>
        <div class="flex-1 text-center md:text-left">
          <h2 class="text-2xl font-bold tracking-tight text-slate-900" style="font-family: var(--font-display);">A note on building Reality Kernel</h2>
          <div class="mt-5 space-y-4 text-slate-600 leading-relaxed text-[15px]">
            <p>The industry is racing to build autonomous systems, but trying to secure them with language models and prompt engineering is mathematically flawed. We recognized that true agent security had to happen at the only layer that matters: the execution layer.</p>
            <p><strong>Keter Labs</strong> (founded 2026) is a deliberately small deep-tech research outfit. We assemble math and people to attack unsolved intelligence problems&#8212;specializing in reflexive intelligence, adversarial systems, and complex systems.</p>
            <p>Reality Kernel is our early founding nucleus. We are focused on proofs and early code rather than marketing. If you believe agent boundaries must be deterministic and enforced offline, you're in the right place.</p>
          </div>
          <div class="mt-6 flex flex-col items-center md:items-start">
            <div class="font-semibold text-slate-900">Tabrez Mukadam</div>
            <div class="text-[13px] font-mono text-slate-500 mt-0.5">Founder, Keter Labs</div>
          </div>
        </div>
      </div>
    </div>
  </section>
'''

if 'founder.jpg' not in index:
    index = index.replace('<!-- @rk:footer-light -->', founder_section + '\n  <!-- @rk:footer-light -->')
    with open('public/index.html', 'w', encoding='utf-8') as f:
        f.write(index)

# 2. Update about.html
with open('public/about.html', 'r', encoding='utf-8') as f:
    about = f.read()
about_content = '''<div class="docs-main" style="max-width:960px;margin:0 auto;">
<section class="docs-block rk-glow-card">
  <h2>The Mission</h2>
  <p><strong>Keter Labs</strong> (founded 2026) is a deliberately small deep-tech research outfit assembling math and people to attack unsolved intelligence problems. We specialize in reflexive intelligence, adversarial systems, and complex systems.</p>
  <p>We operate as an early founding nucleus focused on proofs and early code rather than marketing. While our immediate focus is cryptographic security infrastructure for AI agents via Reality Kernel, our roadmap spans across broad, multidisciplinary intelligence challenges.</p>
</section>
<section class="docs-block rk-glow-card" style="border-bottom:none;">
  <h2>Engineering Philosophy</h2>
  <p>We build security infrastructure, not AI wrappers. Our systems are engineered in Rust, utilizing eBPF for microsecond-level syscall interception, and backed by Ed25519 cryptographic proofs.</p>
  <p>Prompt injections, context smuggling, and role-play jailbreaks cannot be reliably solved at the language level. When an autonomous agent touches infrastructure, we believe the boundary must be deterministic, mathematically provable, and enforced offline.</p>
</section>
</div>'''
about = re.sub(r'<div class="docs-main".*?</div>\s*</main>', about_content + '\n  </main>', about, flags=re.DOTALL)
with open('public/about.html', 'w', encoding='utf-8') as f:
    f.write(about)

# 3. Update privacy.html
with open('public/privacy.html', 'r', encoding='utf-8') as f:
    privacy = f.read()
privacy_content = '''<div class="docs-main" style="max-width:960px;margin:0 auto;">
<section class="docs-block rk-glow-card">
  <h2>Zero-Training Data Retention</h2>
  <p>Your proprietary agent logic, terminal traces, and tool payloads are strictly isolated. <strong>We never use your execution data, logs, or payload contents to train our internal models or any third-party AI models.</strong> Reality Kernel is security infrastructure, not an AI data broker.</p>
</section>
<section class="docs-block rk-glow-card">
  <h2>What we collect</h2>
  <p>We collect only the data needed to enforce cryptographic boundaries and provide auditability:</p>
  <ul>
    <li><strong>Verdict Logs:</strong> We store cryptographically hashed signatures of the commands your agent attempts to run, mapped to an ALLOW/BLOCK status. Sensitive payload contents are redacted or irreversibly hashed before touching our audit ledger.</li>
    <li><strong>Tenant Configuration:</strong> Multi-tenant identifiers, API quotas, policy definitions, and access logs.</li>
    <li><strong>Operational Telemetry:</strong> Standard performance metrics (latency, error rates) to maintain our 0.31ms p50 SLA.</li>
  </ul>
</section>
<section class="docs-block rk-glow-card" style="border-bottom:none;">
  <h2>Contact & Compliance</h2>
  <p>For data deletion requests, GDPR/CCPA inquiries, or security disclosures, contact our compliance team at <a href="mailto:contact@realitykernel.dev">contact@realitykernel.dev</a>.</p>
</section>
</div>'''
privacy = re.sub(r'<div class="docs-main".*?</div>\s*</main>', privacy_content + '\n  </main>', privacy, flags=re.DOTALL)
with open('public/privacy.html', 'w', encoding='utf-8') as f:
    f.write(privacy)

# 4. Update terms.html
with open('public/terms.html', 'r', encoding='utf-8') as f:
    terms = f.read()
terms_content = '''<div class="docs-main" style="max-width:960px;margin:0 auto;">
<section class="docs-block rk-glow-card">
  <h2>Scope of Service & Liability Boundaries</h2>
  <p>Reality Kernel provides execution-layer deterministic containment for autonomous AI agents. We guarantee the structural enforcement of our policy boundaries (the "block") as defined by your host server's cryptographic intent signature.</p>
  <p><strong>We do not guarantee, endorse, or assume liability for the general intelligence, business logic, or downstream outcomes of the agentic systems you build.</strong> You are solely responsible for the agents you deploy.</p>
</section>
<section class="docs-block rk-glow-card">
  <h2>Security Responsibilities</h2>
  <p>You are responsible for securely anchoring your host application. Reality Kernel relies on the intent cryptographic signature provided by your host server. You must protect your Ed25519 signing keys, rotate compromised credentials immediately, and enforce strict RBAC on your Reality Kernel operator console.</p>
</section>
<section class="docs-block rk-glow-card" style="border-bottom:none;">
  <h2>Acceptable Use</h2>
  <p>You agree not to use Reality Kernel to sandbox inherently malicious malware, facilitate denial-of-service attacks, bypass external vendor API rate limits, or orchestrate unauthorized intrusion attempts. Violation of these terms will result in immediate tenant suspension.</p>
  <p>Legal and enterprise questions: <a href="mailto:contact@realitykernel.dev">contact@realitykernel.dev</a></p>
</section>
</div>'''
terms = re.sub(r'<div class="docs-main".*?</div>\s*</main>', terms_content + '\n  </main>', terms, flags=re.DOTALL)
with open('public/terms.html', 'w', encoding='utf-8') as f:
    f.write(terms)

