"""The website states only what the project can back (docs/design/phase-12.md §6).

public/ is a set of static pages. These checks keep it honest and working:
links resolve, nothing of the retired hosted product remains, the README's
rules on performance numbers and superlatives apply to every page, and the
pages stay compatible with the strict Content-Security-Policy in vercel.json.
"""

import html.parser
import importlib.util
import json
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]
PUBLIC = ROOT / "public"
PAGES = sorted(PUBLIC.glob("*.html"))


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


claims = load("readme_claims", ROOT / "tests" / "readme_claims.py")
partials = load("partials", ROOT / "scripts" / "partials.py")


class Page(html.parser.HTMLParser):
    """Links, assets, inline scripts and styles, ids, and the visible prose."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.refs, self.ids, self.text = [], set(), []
        self.inline_scripts = self.style_attrs = 0
        self._skip = 0  # inside <pre>, <code>, <script> or <style>

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if "id" in a:
            self.ids.add(a["id"])
        if "style" in a:
            self.style_attrs += 1
        for key in ("href", "src"):
            if a.get(key):
                self.refs.append(a[key])
        if tag == "script" and not a.get("src"):
            self.inline_scripts += 1
        if tag in ("pre", "code", "script", "style"):
            self._skip += 1

    def handle_endtag(self, tag):
        if tag in ("pre", "code", "script", "style") and self._skip:
            self._skip -= 1

    def handle_data(self, data):
        if not self._skip:
            self.text.append(data)


def parse(path):
    p = Page()
    p.feed(path.read_text(encoding="utf-8"))
    return p


def resolves(ref):
    """Whether a site-relative URL is served by the static site."""
    path = ref.split("#")[0].split("?")[0]
    if path.startswith("/_vercel/"):
        return True  # injected by the host
    if path in ("", "/"):
        return (PUBLIC / "index.html").is_file()
    rel = path.lstrip("/")
    return (PUBLIC / rel).is_file() or (PUBLIC / (rel + ".html")).is_file()


def test_site_links_resolve():
    known = claims.criteria(ROOT)
    problems = []
    for page in PAGES:
        p = parse(page)
        for ref in p.refs:
            if ref.startswith("#"):
                if ref[1:] not in p.ids:
                    problems.append(f"{page.name}: no element {ref}")
            elif ref.startswith("/"):
                if not resolves(ref):
                    problems.append(f"{page.name}: {ref} does not exist")
            elif not ref.startswith(("https://", "mailto:")):
                problems.append(f"{page.name}: unexpected link {ref}")
            for crit in claims.EVIDENCE.findall(ref):
                if crit not in known:
                    problems.append(f"{page.name}: evidence link to unknown criterion {crit}")
    assert PAGES
    assert problems == []


RETIRED = re.compile(
    r"rk_live|api[ _-]?keys?\b|\bcredits?\b|pricing|supabase|\bsign[ -]?in\b|\blog[ -]?in\b|"
    r"playground|/v1/|pip install|request access|sandbox",
    re.IGNORECASE,
)


def test_site_has_no_retired_product():
    problems = []
    for page in PAGES:
        src = page.read_text(encoding="utf-8")
        for m in RETIRED.finditer(src):
            problems.append(f"{page.name}: `{m.group(0)}`")
    assert problems == []


def test_site_claims_rules():
    problems = []
    for page in PAGES:
        text = claims.strip_code(" ".join(parse(page).text))
        for m in claims.PERF_NUMBER.finditer(text):
            problems.append(f"{page.name}: performance number `{m.group(0)}`")
        for word in claims.SUPERLATIVES:
            if word in text.lower():
                problems.append(f"{page.name}: superlative `{word}`")
    assert problems == []


def test_site_partials_current():
    for page in PAGES:
        src = page.read_text(encoding="utf-8")
        assert partials.expand(src) == src, f"{page.name}: run scripts/partials.py"
        for name in partials.PARTIALS:
            assert f"<!-- @rk:{name} -->" in src, f"{page.name}: no {name} partial"


def test_site_fits_the_content_security_policy():
    config = json.loads((ROOT / "vercel.json").read_text(encoding="utf-8"))
    headers = {h["key"]: h["value"] for rule in config["headers"] for h in rule["headers"]}
    csp = headers["Content-Security-Policy"]
    assert "script-src 'self';" in csp and "style-src 'self';" in csp
    assert "unsafe-inline" not in csp and "unsafe-eval" not in csp
    for page in PAGES:
        p = parse(page)
        assert p.inline_scripts == 0, f"{page.name}: inline <script>"
        assert p.style_attrs == 0, f"{page.name}: style attribute"
        assert "<style" not in page.read_text(encoding="utf-8"), f"{page.name}: <style> element"


def test_site_config_and_sitemap():
    config = json.loads((ROOT / "vercel.json").read_text(encoding="utf-8"))
    # A static site whatever the dashboard says: `"framework": null` is Vercel's
    # "Other" preset, so with no package.json nothing is installed or built.
    assert config["framework"] is None
    assert not (ROOT / "package.json").exists()
    assert "rewrites" not in config and "functions" not in config
    assert not (PUBLIC / "vercel.json").exists(), "only the repository root holds vercel.json"
    for r in config["redirects"]:
        assert resolves(r["destination"]), r
        assert not resolves(r["source"]), f"{r['source']} redirects but still exists"
    listed = set(re.findall(r"<loc>https://www\.realitykernel\.dev/([^<]*)</loc>",
                            (PUBLIC / "sitemap.xml").read_text(encoding="utf-8")))
    pages = {"" if p.stem == "index" else p.stem for p in PAGES if p.stem != "404"}
    assert listed == pages
