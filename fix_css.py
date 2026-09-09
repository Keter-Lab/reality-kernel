import re

with open('public/tw.css', 'r', encoding='utf-8') as f:
    text = f.read()

# Remove the entire dark mode extensions block from tw.css
text = re.sub(r'/\* === RK DARK MODE EXTENSIONS.*?RK-FOOTER-SOCIAL.*?\n', '', text, flags=re.DOTALL)
text = re.sub(r'/\* === RK DARK MODE EXTENSIONS.*$', '', text, flags=re.DOTALL)

with open('public/tw.css', 'w', encoding='utf-8') as f:
    f.write(text)
