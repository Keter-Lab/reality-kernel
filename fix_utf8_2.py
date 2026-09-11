import os

for file in os.listdir('public'):
    if file.endswith('.html'):
        filepath = os.path.join('public', file)
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            text = f.read()

        text = text.replace('Keter Labs A Cryptographic', 'Keter Labs &bull; Cryptographic')
        text = text.replace('Ac 2026 Reality Kernel A All', '&copy; 2026 Reality Kernel &bull; All')
        text = text.replace('A Reality Kernel', '| Reality Kernel')
        
        # In case the exact char isn't standard:
        import re
        text = re.sub(r'Keter Labs A[^\s]* Cryptographic', 'Keter Labs &bull; Cryptographic', text)
        text = re.sub(r'Ac 2026 Reality Kernel A[^\s]* All', '&copy; 2026 Reality Kernel &bull; All', text)

        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(text)
