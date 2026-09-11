import re

with open('public/index.html', 'r', encoding='utf-8') as f:
    text = f.read()

# 1. Remove the big founder section completely
text = re.sub(r'<section class=\"py-24 bg-slate-50 border-t border-slate-200\">.*?</section>\n\n  <!-- @rk:footer-light -->', '<!-- @rk:footer-light -->', text, flags=re.DOTALL)

# 2. Add a small box quote for the founder right above the CTA / before the footer
# Let's insert it right after the closing </main>
founder_box = '''
  <div class="mx-auto max-w-4xl px-5 py-12">
    <div class="rounded-xl border border-slate-200 bg-white p-6 sm:p-8 flex flex-col sm:flex-row items-center gap-6 shadow-sm">
      <img src="/founder.jpg" alt="Tabrez Mukadam" class="w-20 h-20 rounded-full object-cover border border-slate-100 shadow-sm shrink-0" />
      <div>
        <p class="text-sm text-slate-600 leading-relaxed">"The industry is racing to build autonomous systems, but trying to secure them with language models is mathematically flawed. We believe agent boundaries must be deterministic, built in Rust, and enforced offline. That's why we built Reality Kernel."</p>
        <div class="mt-3 text-sm font-semibold text-slate-900">Tabrez Mukadam <span class="font-normal text-slate-500 font-mono text-xs ml-1">Founder, Keter Labs</span></div>
      </div>
    </div>
  </div>
'''
text = text.replace('</main>', '</main>\n' + founder_box)

# 3. Fix the sandbox overlap (max-w-5xl -> max-w-6xl)
text = text.replace('<div id="threat-sandbox" class="grid grid-cols-1 lg:grid-cols-2 gap-8 max-w-5xl mx-auto mt-12', '<div id="threat-sandbox" class="grid grid-cols-1 lg:grid-cols-2 gap-10 max-w-6xl mx-auto mt-12')

# Also fix the right-8 absolute positioning inside the diagram
text = text.replace('right-8', 'right-4')

with open('public/index.html', 'w', encoding='utf-8') as f:
    f.write(text)
