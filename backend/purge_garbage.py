
import os
import re

file_path = r"c:\Users\khanj\Matrix\backend\agents\github_agent.py"

with open(file_path, 'r', encoding='utf-8') as f:
    lines = f.readlines()

new_lines = []

KEEP_STARTS = (
    'def ', 'class ', 'async ', 'await ', 'return', 'if ', 'else', 'elif ', 
    'for ', 'while ', 'try', 'except', 'finally', 'with ', 'pass', 'continue', 
    'break', 'raise ', 'import ', 'from ', 'del ', 'assert ', 'global ', 'nonlocal ',
    'self.', 'logger.', 'super(', 'print(', '@',
    '#', '"', "'", 'r"', "r'", 'f"', "f'"
)

# Also keep lines that encompass function calls or multi-line structures
# Simplest check: if it has symbols like = ( ) { } [ ] :
HAS_SYMBOLS = re.compile(r'[=\(\)\{\}\[\]:]')

for line in lines:
    stripped = line.strip()
    
    if not stripped:
        new_lines.append(line)
        continue
        
    # Heuristic 1: Known keywords
    if stripped.startswith(KEEP_STARTS):
        new_lines.append(line)
        continue
        
    # Heuristic 2: Symbols indicating code
    if HAS_SYMBOLS.search(stripped):
        new_lines.append(line)
        continue
        
    # Heuristic 3: If it's pure text (letters, spaces, punctuation) it's likely garbage docstring
    # But wait, what about multi-line function args?
    # e.g. "param1," -> ends with comma.
    if stripped.endswith(','):
        new_lines.append(line)
        continue
        
    # If we are here, it's likely garbage text like "Scan a GitHub repository."
    print(f"Purging garbage line: {stripped[:50]}...")

with open(file_path, 'w', encoding='utf-8') as f:
    f.writelines(new_lines)

print(f"Purged garbage from {file_path}")
