#!/usr/bin/env python3
"""
Static partial injector for the public portal.

Every public HTML page contains:
    <!-- @rk:header -->  ...  <!-- @rk:/header -->
    <!-- @rk:footer -->  ...  <!-- @rk:/footer -->
Running this script rewrites the content between the markers so the global
navigation and footer stay byte-identical across all pages. No build step is
required at deploy time — the committed HTML is already expanded.

    python3 scripts/partials.py          # rewrite all public/*.html
    python3 scripts/partials.py --check  # exit 1 if any page is stale
"""
import re, sys, pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent / "public"

HEADER = """<!-- @rk:header -->
  <header class="rk-header">
    <a href="/" class="rk-brand">
      <div class="brand">
        <div class="brand-mark"><img src="/logo.png" alt="Reality Kernel" width="38" height="38" /></div>
        <div>
          <strong>REALITY KERNEL <span class="badge-beta">BETA</span></strong>
          <span class="brand-sub">Execution-layer security</span>
        </div>
      </div>
    </a>
    <nav class="rk-nav">
      <a href="/playground">Playground</a>
      <a href="/verifier">Verifier</a>
      <a href="/docs">Docs</a>
      <a href="/security">Security</a>
      <a href="/pricing">Pricing</a>
    </nav>
    <div class="rk-header-cta">
      <a href="/login" class="btn btn-sm ghost" data-auth="signin">Sign in</a>
      <a href="/login#request" class="btn btn-sm" data-auth="request">Request Access</a>
      <button class="rk-menu-toggle" type="button" aria-label="Toggle navigation">
        <svg viewBox="0 0 24 24"><path d="M4 7h16M4 12h16M4 17h16"/></svg>
      </button>
    </div>
  </header>
  <!-- @rk:/header -->"""

FOOTER = """<!-- @rk:footer -->
  <footer class="rk-footer">
    <div class="rk-footer-inner">
      <div class="rk-footer-brand">
        <div class="brand small">
          <div class="brand-mark"><img src="/logo.png" alt="Reality Kernel" /></div>
          <div>
            <strong>REALITY KERNEL</strong>
            <span class="brand-sub">Keter Labs · Cryptographic Security Division</span>
          </div>
        </div>
        <p>Execution-layer security and a cryptographic audit ledger for autonomous AI agents. Deterministic boundaries. Signed verdicts. Verifiable history.</p>
      </div>
      <div>
        <h5>Product</h5>
        <ul>
          <li><a href="/playground">Playground</a></li>
          <li><a href="/verifier">Verifier</a></li>
          <li><a href="/pricing">Pricing</a></li>
          <li><a href="/benchmark">Benchmark</a></li>
        </ul>
      </div>
      <div>
        <h5>Developers</h5>
        <ul>
          <li><a href="/docs">Integration guide</a></li>
          <li><a href="/sdk">SDK reference</a></li>
          <li><a href="/docs#api">API reference</a></li>
          <li><a href="/login#request">Request sandbox</a></li>
        </ul>
      </div>
      <div>
        <h5>Trust</h5>
        <ul>
          <li><a href="/security">Security &amp; threat model</a></li>
          <li><a href="/faq">FAQ</a></li>
          <li><a href="mailto:contact@realitykernel.dev">contact@realitykernel.dev</a></li>
          <li><a href="https://www.linkedin.com/company/keter-labs/" target="_blank" rel="noopener">Keter Labs</a></li>
        </ul>
      </div>
    </div>
    <div class="rk-footer-bottom">
      <span>© 2025 Reality Kernel · All rights reserved</span>
      <span class="rk-status"><span class="pulse"></span>API v0.4.2 · Ed25519 signing active</span>
    </div>
  </footer>
  <!-- @rk:/footer -->"""

# ---------------------------------------------------------------------------
# Light-theme variants (Tailwind) used by the landing interface. Same links as
# the dark header/footer so every route remains reachable from every page.
# ---------------------------------------------------------------------------
NAV_LINKS = [
    ("/playground", "Playground"),
    ("/verifier", "Verifier"),
    ("/docs", "Docs"),
    ("/security", "Security"),
    ("/pricing", "Pricing"),
]

HEADER_LIGHT = """<!-- @rk:header-light -->
  <header class="rk-header fixed inset-x-0 top-0 z-50 border-b border-slate-200/70 bg-white/80 backdrop-blur-xl">
    <div class="mx-auto flex h-16 max-w-7xl items-center justify-between gap-4 px-4 sm:gap-6 sm:px-8">
      <a href="/" class="rk-brand flex items-center gap-3">
        <span class="flex h-9 w-9 items-center justify-center rounded-xl border border-slate-200 bg-white shadow-sm"><img src="/logo.png" alt="Reality Kernel" width="26" height="26" class="h-[26px] w-[26px]" /></span>
        <span class="leading-none">
          <span class="block text-[13px] font-bold tracking-[0.12em] text-slate-900">REALITY KERNEL</span>
          <span class="mt-1 hidden font-mono text-[10px] uppercase tracking-[0.16em] text-slate-400 sm:block">Execution-layer security</span>
        </span>
      </a>
      <nav class="rk-nav absolute inset-x-0 top-16 hidden flex-col gap-1 border-b border-slate-200 bg-white p-3 shadow-card md:static md:flex md:flex-row md:items-center md:gap-1 md:border-0 md:bg-transparent md:p-0 md:shadow-none">
""" + "\n".join('        <a href="%s" class="nav-link">%s</a>' % l for l in NAV_LINKS) + """
      </nav>
      <div class="rk-header-cta flex items-center gap-2">
        <a href="/login" class="btn-secondary hidden !py-2 sm:inline-flex" data-auth="signin">Sign in</a>
        <a href="/login#request" class="btn-primary whitespace-nowrap !px-3 !py-2 sm:!px-4" data-auth="request">Request Access</a>
        <button class="rk-menu-toggle inline-flex h-9 w-9 items-center justify-center rounded-lg border border-slate-200 bg-white text-slate-700 md:hidden" type="button" aria-label="Toggle navigation">
          <svg viewBox="0 0 24 24" class="h-4 w-4" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M4 7h16M4 12h16M4 17h16"/></svg>
        </button>
      </div>
    </div>
  </header>
  <!-- @rk:/header-light -->"""

FOOTER_LIGHT = """<!-- @rk:footer-light -->
  <footer class="border-t border-slate-200/80 bg-white">
    <div class="mx-auto grid max-w-7xl gap-10 px-5 py-14 sm:px-8 md:grid-cols-[1.4fr_1fr_1fr_1fr]">
      <div>
        <div class="flex items-center gap-3">
          <span class="flex h-9 w-9 items-center justify-center rounded-xl border border-slate-200 bg-white shadow-sm"><img src="/logo.png" alt="Reality Kernel" class="h-[26px] w-[26px]" /></span>
          <span class="leading-none">
            <span class="block text-[13px] font-bold tracking-[0.12em] text-slate-900">REALITY KERNEL</span>
            <span class="mt-1 block font-mono text-[10px] uppercase tracking-[0.16em] text-slate-400">Keter Labs · Cryptographic Security Division</span>
          </span>
        </div>
        <p class="mt-5 max-w-sm text-sm leading-6 text-slate-500">Execution-layer security and a cryptographic audit ledger for autonomous AI agents. Deterministic boundaries. Signed verdicts. Verifiable history.</p>
      </div>
      <div>
        <h5 class="font-mono text-[11px] uppercase tracking-[0.18em] text-slate-400">Product</h5>
        <ul class="mt-4 space-y-2.5 text-sm">
          <li><a class="text-slate-600 hover:text-slate-900" href="/playground">Playground</a></li>
          <li><a class="text-slate-600 hover:text-slate-900" href="/verifier">Verifier</a></li>
          <li><a class="text-slate-600 hover:text-slate-900" href="/pricing">Pricing</a></li>
          <li><a class="text-slate-600 hover:text-slate-900" href="/benchmark">Benchmark</a></li>
        </ul>
      </div>
      <div>
        <h5 class="font-mono text-[11px] uppercase tracking-[0.18em] text-slate-400">Developers</h5>
        <ul class="mt-4 space-y-2.5 text-sm">
          <li><a class="text-slate-600 hover:text-slate-900" href="/docs">Integration guide</a></li>
          <li><a class="text-slate-600 hover:text-slate-900" href="/sdk">SDK reference</a></li>
          <li><a class="text-slate-600 hover:text-slate-900" href="/docs#api">API reference</a></li>
          <li><a class="text-slate-600 hover:text-slate-900" href="/login#request">Request sandbox</a></li>
        </ul>
      </div>
      <div>
        <h5 class="font-mono text-[11px] uppercase tracking-[0.18em] text-slate-400">Trust</h5>
        <ul class="mt-4 space-y-2.5 text-sm">
          <li><a class="text-slate-600 hover:text-slate-900" href="/security">Security &amp; threat model</a></li>
          <li><a class="text-slate-600 hover:text-slate-900" href="/faq">FAQ</a></li>
          <li><a class="text-slate-600 hover:text-slate-900" href="mailto:contact@realitykernel.dev">contact@realitykernel.dev</a></li>
          <li><a class="text-slate-600 hover:text-slate-900" href="https://www.linkedin.com/company/keter-labs/" target="_blank" rel="noopener">Keter Labs</a></li>
        </ul>
      </div>
    </div>
    <div class="border-t border-slate-200/80">
      <div class="mx-auto flex max-w-7xl flex-col gap-2 px-5 py-5 font-mono text-[11px] text-slate-400 sm:flex-row sm:items-center sm:justify-between sm:px-8">
        <span>© 2025 Reality Kernel · All rights reserved</span>
        <span class="inline-flex items-center gap-2"><span class="h-1.5 w-1.5 rounded-full bg-emerald-500"></span>API v0.4.2 · Ed25519 signing active</span>
      </div>
    </div>
  </footer>
  <!-- @rk:/footer-light -->"""

PARTIALS = {"header": HEADER, "footer": FOOTER, "header-light": HEADER_LIGHT, "footer-light": FOOTER_LIGHT}

def expand(html: str) -> str:
    for name, body in PARTIALS.items():
        pat = re.compile(r"<!-- @rk:%s -->.*?<!-- @rk:/%s -->" % (name, name), re.S)
        html = pat.sub(lambda m: body, html)
    return html

def main():
    check = "--check" in sys.argv
    stale = []
    for p in sorted(ROOT.glob("*.html")):
        src = p.read_text(encoding="utf-8")
        if "@rk:" not in src:
            continue
        out = expand(src)
        if out != src:
            stale.append(p.name)
            if not check:
                p.write_text(out, encoding="utf-8")
    if check:
        if stale:
            print("STALE partials in:", ", ".join(stale)); sys.exit(1)
        print("partials OK")
    else:
        print("updated:", ", ".join(stale) if stale else "(nothing)")

if __name__ == "__main__":
    main()
