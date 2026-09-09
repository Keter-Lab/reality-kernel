import os
import re

for file in os.listdir('public'):
    if file.endswith('.html'):
        filepath = os.path.join('public', file)
        with open(filepath, 'r', encoding='utf-8') as f:
            text = f.read()

        # Fix title tags
        text = text.replace(' A ', ' | ')
        # Fix copyright
        text = text.replace('Ac 2026', '&copy; 2026')
        # Fix other bullets
        text = text.replace('?', '&bull;')
        text = text.replace('', '')

        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(text)

# Fix landing.js just in case
with open('public/landing.js', 'r', encoding='utf-8') as f:
    landing = f.read()
landing = landing.replace('?', '&bull;')
landing = landing.replace('', '')
with open('public/landing.js', 'w', encoding='utf-8') as f:
    f.write(landing)

