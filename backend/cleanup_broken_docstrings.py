
import os

file_path = r"c:\Users\khanj\Matrix\backend\agents\github_agent.py"

with open(file_path, 'r', encoding='utf-8') as f:
    lines = f.readlines()

new_lines = []
in_broken_docstring = False

for line in lines:
    stripped = line.strip()
    if stripped.startswith('# """') or stripped.startswith('#"""'):
        # Toggle state
        in_broken_docstring = not in_broken_docstring
        continue # Skip the marker line itself
    
    if in_broken_docstring:
        # We are inside the text that used to be a docstring.
        # Skip it (delete it).
        continue
    
    new_lines.append(line)

with open(file_path, 'w', encoding='utf-8') as f:
    f.writelines(new_lines)

print(f"Cleaned {file_path}")
