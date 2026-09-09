import os
import re

for file in os.listdir('public'):
    if file.endswith('.html'):
        filepath = os.path.join('public', file)
        with open(filepath, 'rb') as f:
            btext = f.read()
            
        btext = re.sub(b'.*2026 Reality Kernel.*All rights reserved', b'&copy; 2026 Reality Kernel &bull; All rights reserved', btext)

        with open(filepath, 'wb') as f:
            f.write(btext)

