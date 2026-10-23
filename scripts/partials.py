#!/usr/bin/env python3
"""
Static partial injector for the website (public/).

Every page contains three marker pairs:
    <!-- @rk:head -->    ...  <!-- @rk:/head -->     (stylesheet, fonts, script)
    <!-- @rk:header -->  ...  <!-- @rk:/header -->   (navigation)
    <!-- @rk:footer -->  ...  <!-- @rk:/footer -->
Running this script rewrites the content between the markers so they stay
identical across pages. No build step is required at deploy time: the
committed HTML is already expanded.

    python3 scripts/partials.py          # rewrite all public/*.html
    python3 scripts/partials.py --check  # exit 1 if any page is stale
"""
import re, sys, pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent / "public"

REPO = "https://github.com/Keter-Lab/reality-kernel"
BLURB = ("Open-source, kernel-level enforcement for AI agents on Linux: network, exec "
         "and file policy decided in eBPF, with a signed audit log.")

NAV_LINKS = [
    ("/", "Home"),
    ("/docs", "Docs"),
    ("/security", "Security"),
    ("/about", "About"),
]

FOOTER_COLUMNS = [
    ("Project", [
        (REPO, "GitHub"),
        (REPO + "/releases", "Releases"),
        (REPO + "/blob/main/CHANGELOG.md", "Changelog"),
        (REPO + "/blob/main/CONTRIBUTING.md", "Contributing"),
    ]),
    ("Documentation", [
        ("/docs", "All documentation"),
        (REPO + "/blob/main/docs/install.md", "Install"),
        (REPO + "/blob/main/docs/policy.md", "Policy reference"),
        (REPO + "/blob/main/docs/evidence.md", "Evidence"),
    ]),
    ("Trust", [
        ("/security", "Security"),
        ("/about", "About"),
        ("/privacy", "Privacy"),
        ("/terms", "Terms"),
        ("/cookies", "Cookies"),
    ]),
]

GITHUB_PATH = ("M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 "
               "0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466"
               "-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647"
               ".35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446"
               "-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909"
               "-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848"
               "-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688"
               ".482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z")
GITHUB_SVG = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="%s"/></svg>' % GITHUB_PATH
MAIL_SVG = ('<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M3 6.75A1.75 1.75 0 0 1 4.75 5h14.5A1.75 1.75 0 0 1 21 6.75v10.5'
            'A1.75 1.75 0 0 1 19.25 19H4.75A1.75 1.75 0 0 1 3 17.25V6.75zm1.8.35v.2L12 12.1l7.2-4.8v-.2a.3.3 0 0 0-.3-.3'
            'H5.1a.3.3 0 0 0-.3.3zm14.4 2.36-6.7 4.47a.9.9 0 0 1-1 0L4.8 9.46v7.79c0 .17.13.3.3.3h13.8a.3.3 0 0 0 .3-.3V9.46z"/></svg>')
LINKEDIN_SVG = ('<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M6.94 8.5A1.56 1.56 0 1 1 6.93 5.4a1.56 1.56 0 0 1 .01 3.1z'
                'M5.5 9.75h2.88V19H5.5V9.75zm5.07 0h2.76v1.26h.04c.38-.72 1.33-1.48 2.74-1.48 2.93 0 3.47 1.93 3.47 4.45'
                'V19h-2.88v-4.44c0-1.06-.02-2.42-1.47-2.42-1.47 0-1.69 1.15-1.69 2.34V19h-2.88V9.75z"/></svg>')


def link(href, label, cls=""):
    attrs = ' class="%s"' % cls if cls else ""
    if href.startswith("http"):
        attrs += ' rel="noopener"'
    return '<a href="%s"%s>%s</a>' % (href, attrs, label)


HEAD = """<!-- @rk:head -->
  <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover" />
  <meta name="color-scheme" content="light dark" />
  <meta name="theme-color" content="#f3f5f8" media="(prefers-color-scheme: light)" />
  <meta name="theme-color" content="#090e19" media="(prefers-color-scheme: dark)" />
  <link rel="preload" href="/fonts/ibm-plex-sans-var-latin.woff2" as="font" type="font/woff2" crossorigin />
  <link rel="stylesheet" href="/site.css" />
  <link rel="icon" href="/favicon.ico" sizes="any" />
  <link rel="apple-touch-icon" href="/favicon.png" />
  <script src="/app.js"></script>
  <script defer src="/_vercel/speed-insights/script.js"></script>
  <!-- @rk:/head -->"""

HEADER = """<!-- @rk:header -->
  <a class="skip" href="#main">Skip to content</a>
  <header class="site-header">
    <div class="wrap">
      <a href="/" class="brand">
        <img src="/logo.png" alt="" width="30" height="30" />
        <span class="brand-text"><strong>Reality Kernel</strong><span>eBPF enforcement for AI agents</span></span>
      </a>
      <nav class="nav" id="site-nav" aria-label="Main">
""" + "\n".join("        " + link(h, l) for h, l in NAV_LINKS) + """
      </nav>
      <div class="header-actions">
        <a class="icon-btn" href=\"""" + REPO + """\" rel="noopener" aria-label="Reality Kernel on GitHub">""" + GITHUB_SVG.replace("<svg ", '<svg class="fill" ') + """</a>
        <button class="icon-btn menu-toggle" type="button" aria-controls="site-nav" aria-expanded="false" aria-label="Menu">
          <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 7h16M4 12h16M4 17h16"/></svg>
        </button>
      </div>
    </div>
  </header>
  <!-- @rk:/header -->"""

FOOTER = """<!-- @rk:footer -->
  <footer class="site-footer">
    <div class="wrap">
      <div class="footer-grid">
        <div>
          <a href="/" class="brand"><img src="/logo.png" alt="" width="30" height="30" /><span class="brand-text"><strong>Reality Kernel</strong><span>by Keter Labs</span></span></a>
          <p>""" + BLURB + """</p>
        </div>
""" + "\n".join(
    '        <nav aria-label="%s">\n          <h2>%s</h2>\n          <ul>\n%s\n          </ul>\n        </nav>' % (
        title, title, "\n".join("            <li>%s</li>" % link(h, l) for h, l in links))
    for title, links in FOOTER_COLUMNS) + """
      </div>
      <div class="footer-bottom">
        <span>&copy; 2026 Keter Labs &middot; Code licensed MIT OR Apache-2.0</span>
        <span class="social">
          <a href="mailto:contact@realitykernel.dev" aria-label="Email contact@realitykernel.dev">""" + MAIL_SVG + """</a>
          <a href=\"""" + REPO + """\" rel="noopener" aria-label="GitHub">""" + GITHUB_SVG + """</a>
          <a href="https://www.linkedin.com/company/keter-labs/" rel="noopener" aria-label="Keter Labs on LinkedIn">""" + LINKEDIN_SVG + """</a>
        </span>
      </div>
    </div>
  </footer>
  <!-- @rk:/footer -->"""

PARTIALS = {"head": HEAD, "header": HEADER, "footer": FOOTER}


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
        missing = [n for n in PARTIALS if "<!-- @rk:%s -->" % n not in src]
        if missing:
            print("%s: missing partials %s" % (p.name, ", ".join(missing))); sys.exit(1)
        out = expand(src)
        if out != src:
            stale.append(p.name)
            if not check:
                p.write_text(out, encoding="utf-8", newline="\n")
    if check:
        if stale:
            print("STALE partials in:", ", ".join(stale)); sys.exit(1)
        print("partials OK")
    else:
        print("updated:", ", ".join(stale) if stale else "(nothing)")


if __name__ == "__main__":
    main()
