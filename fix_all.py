import os, re

# Fix 1: Add Home to nav in ALL html files that use the old styles.css nav pattern
html_files = [f for f in os.listdir('public') if f.endswith('.html') and f != 'index.html']

old_nav = '<nav class="rk-nav">\n        <a href="/playground">Playground</a>'
new_nav = '<nav class="rk-nav">\n        <a href="/">Home</a>\n        <a href="/playground">Playground</a>'

for fname in html_files:
    fpath = os.path.join('public', fname)
    with open(fpath, 'r', encoding='utf-8') as f:
        text = f.read()
    if old_nav in text:
        text = text.replace(old_nav, new_nav)
        with open(fpath, 'w', encoding='utf-8') as f:
            f.write(text)
        print(f'Fixed nav in {fname}')
    else:
        print(f'Nav pattern not found in {fname}')

# Fix 2: Replace the founder section in index.html with a proper full-width section
with open('public/index.html', 'r', encoding='utf-8') as f:
    idx = f.read()

old_founder = '''  <div class="mx-auto max-w-5xl px-5 py-14 sm:px-8">
    <div class="rounded-2xl border border-slate-200 bg-white p-8 sm:p-10 flex flex-col sm:flex-row items-center sm:items-start gap-8 shadow-md">
      <img src="/founder.jpg" alt="Tabrez Mukadam" class="w-28 h-28 sm:w-32 sm:h-32 rounded-full object-cover border border-slate-100 shadow-md shrink-0" />
      <div class="flex-1 text-center sm:text-left">
        <p class="text-base text-slate-600 leading-relaxed">"The industry is racing to build autonomous systems, but trying to secure them with language models is mathematically flawed. We believe agent boundaries must be deterministic, built in Rust, and enforced offline. That\'s why we built Reality Kernel."</p>
        <div class="mt-4 text-sm font-semibold text-slate-900">Tabrez Mukadam <span class="font-normal text-slate-500 font-mono text-xs ml-1">— Founder, Keter Labs</span></div>
      </div>
    </div>
  </div>'''

new_founder = '''  <section class="border-t border-slate-200/80 bg-white">
    <div class="mx-auto max-w-5xl px-5 py-16 sm:px-8">
      <div class="flex flex-col sm:flex-row items-center sm:items-start gap-8">
        <img src="/founder.jpg" alt="Tabrez Mukadam" class="w-28 h-28 sm:w-32 sm:h-32 rounded-full object-cover border-2 border-slate-200 shadow-lg shrink-0" />
        <div class="flex-1 text-center sm:text-left">
          <p class="text-[15px] leading-relaxed text-slate-600 italic">"The industry is racing to build autonomous systems, but trying to secure them with language models is mathematically flawed. We believe agent boundaries must be deterministic, built in Rust, and enforced offline. That\'s why we built Reality Kernel."</p>
          <div class="mt-5 flex flex-col sm:flex-row sm:items-center gap-1 sm:gap-3">
            <span class="font-bold text-slate-900">Tabrez Mukadam</span>
            <span class="hidden sm:block text-slate-300">|</span>
            <span class="font-mono text-xs text-slate-500">Founder, Keter Labs</span>
          </div>
        </div>
      </div>
    </div>
  </section>'''

if old_founder in idx:
    idx = idx.replace(old_founder, new_founder)
    print('Fixed founder section')
else:
    print('WARNING: founder pattern not found - check manually')

with open('public/index.html', 'w', encoding='utf-8') as f:
    f.write(idx)
