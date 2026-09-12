import os

target_files = [
    r'C:\Users\Tabrez\Downloads\rk-temp-clone\public\integration.html',
    r'C:\Users\Tabrez\Downloads\rk-temp-clone\public\sdk.html'
]

for file_path in target_files:
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Replace any plain 'class="docs-block"' with 'class="docs-block rk-glow-card"'
    # Also handle if it has an id
    modified = content.replace('class="docs-block"', 'class="docs-block rk-glow-card"')
    
    # In case there's already some with rk-glow-card, we might have doubled it. Let's fix that.
    modified = modified.replace('rk-glow-card rk-glow-card', 'rk-glow-card')
    
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(modified)
    print(f"Updated {file_path}")
