# Design note: Phase 14 — the website, rebuilt around the Warden

Status: **ACCEPTED** (2026-10-23; the maintainer reviewed the local preview
and approved it).
Branch: `phase-14-site` (from `main` at eb22d00)

## 1. Goal and acceptance criteria

Give realitykernel.dev an identity of its own, consistent on every page,
that shows what the product does rather than describing it.

1. One visual system on every page: the same tokens, header, footer and
   section patterns. No page keeps the old layout.
2. The site has two modes, `enforce` and `audit`, mirroring a profile's
   modes. A switch in the header changes the signal colour, the hero
   behaviour and the copy that differs between modes; the choice persists.
3. A character, the Warden (an owl), watches system calls cross the kernel
   boundary in the hero: denied calls are knocked back with `-1 EPERM` in
   enforce mode and let through as would-deny in audit mode.
4. Nothing breaks the existing Content Security Policy (`script-src 'self'`,
   `style-src 'self'`): no inline scripts, `<style>` elements or `style`
   attributes.
5. Motion is decorative only. With `prefers-reduced-motion` every page draws
   a still frame; with JavaScript off, every page is complete and readable.
6. Fonts are self-hosted under the SIL Open Font License; the site adds no
   third-party requests.
7. The existing site tests (`tests/test_site.py`: links, anchors, evidence
   links, retired-product words, README claim rules, CSP, partials, sitemap,
   Vercel config) pass unchanged.

## 2. Design

**Surfaces.** Basalt (`#08090c`) dark bands carry the story; light "paper"
panels carry anything meant to be read at length (capabilities, docs,
policies). Terminal surfaces stay terminal-dark everywhere. One signal
colour follows the mode: cobalt `#7a8dff` in enforce, amber `#f2b33d` in
audit. EPERM red is reserved for denials.

**Type.** Instrument Serif for headlines and the wordmark, with the signal
phrase of each headline in italic; IBM Plex Sans for body text; IBM Plex
Mono for system labels and code. A display serif against terminal mono reads
as a signed record, which is what the audit log is. Anton and Martian
Mono were tried in review and dropped.

**Mode system.** `html[data-mode]`, saved in `localStorage` (`rk-mode`),
applied by `app.js` in `<head>` before first paint. `window.rkMode` and an
`rk:mode` event let the other scripts follow. Copy that differs between
modes is marked `.when-enforce` / `.when-audit`, so both versions are in the
HTML and readable without JavaScript.

**Hero.** Two layered canvases:

- `owl3d.js`: the Warden as a point cloud (about 6,000 points) in raw WebGL
  with additive blending. It assembles on load, dissolves as the page
  scrolls, follows the pointer, flares on each enforce denial and scans with
  half-lidded eyes in audit mode. On a shader or context failure it removes
  `html.owl-3d` and the 2D owl in `hero.js` takes over.
- `hero.js`: syscall lanes. Calls rise from user space; allowed calls pass,
  denied ones bounce with `-1 EPERM` (enforce) or pass marked
  `AUDIT · would deny` (audit). Each denial emits `rk:hit` for the owl.

**Site-wide (`warden.js`).** A reticle cursor that locks onto links and
buttons and names the system call the action would make; magnetic buttons;
mono labels that decode from terminal glyphs and serif headings that ink in;
a scroll-progress boundary line under the header with the owl riding it; and
a small perched Warden that appears once the hero is out of view (eyes
follow the pointer; clicking it switches mode). All pointer effects are off
on touch screens; the whole script exits under reduced motion. The system
cursor is never hidden.

**Pages.** Home is rebuilt (hero, the boundary with an strace / audit-tail
figure and a layer diagram, capabilities on paper, how it works, quick
start, tested kernels, closing). Docs, security, about, privacy, terms,
cookies and 404 use the same `page-head` stage and `prose` paper panel.
Hash-chain "batch" dividers between home sections echo the audit log.

## 3. Verification

- `tests/test_site.py`: all tests pass; `scripts/partials.py --check` clean.
- `node --check` on every script; `hero.js` run for 600 frames against a
  stub canvas without errors.
- Headless Edge screenshots (SwiftShader WebGL) of every page at 1440 px and
  phone widths (360 and 390 px), in both modes and with reduced motion.
- Reviewed by the maintainer on a local preview server before the push.

## 4. Not in scope

A light theme; per-page Open Graph images; translating the site.
