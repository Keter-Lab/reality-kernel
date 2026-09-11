import os, glob

search_dir = 'C:/Users/Tabrez/Downloads/rk-temp-clone/public'
for file in glob.glob(os.path.join(search_dir, '*.html')):
    with open(file, 'r', encoding='utf-8') as f:
        content = f.read()

    modified = False
    
    # 1. Simple nav (e.g. integration.html, verifier.html)
    if 'href="/playground"' in content and 'href="/demo.html"' not in content:
        if '<a href="/">Home</a>' in content:
            content = content.replace('<a href="/">Home</a>', '<a href="/">Home</a>\n      <a href="/demo.html">Demo</a>')
            modified = True
            
    # 2. index.html nav
    if 'class="nav-link">Home</a>' in content and 'href="/demo.html"' not in content:
        content = content.replace('<a href="/" class="nav-link">Home</a>', '<a href="/" class="nav-link">Home</a>\n        <a href="/demo.html" class="nav-link">Demo</a>')
        modified = True

    # 3. dashboard.html nav
    if 'href="/verifier"' in content and 'class="rk-nav-link external"' in content and 'href="/demo.html"' not in content:
        new_link = """        <a class="rk-nav-link external" href="/demo.html">
          <span class="nav-ic"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><polygon points="10 8 16 12 10 16 10 8"/></svg></span>
          Tour
        </a>\n"""
        content = content.replace('<a class="rk-nav-link external" href="/verifier">', new_link + '        <a class="rk-nav-link external" href="/verifier">')
        modified = True

    if modified:
        with open(file, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f'Updated {file}')
