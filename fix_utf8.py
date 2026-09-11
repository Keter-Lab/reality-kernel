import os
import re

for file in os.listdir('public'):
    if file.endswith('.html'):
        filepath = os.path.join('public', file)
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            text = f.read()

        # Fix specific bad strings
        text = re.sub(r'Keter Labs A. Cryptographic', 'Keter Labs &bull; Cryptographic', text)
        text = re.sub(r'Ac 2026 Reality Kernel A. All', '&copy; 2026 Reality Kernel &bull; All', text)
        text = re.sub(r'A. Reality Kernel', '| Reality Kernel', text)

        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(text)

