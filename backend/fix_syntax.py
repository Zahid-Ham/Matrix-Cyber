
import os

file_path = r"c:\Users\khanj\Matrix\backend\agents\github_agent.py"

with open(file_path, 'r', encoding='utf-8') as f:
    content = f.read()

# Naive replacement of triple quotes to avoid syntax errors
# This turns docstrings into strings (if assigned) or just expressions.
# But "unterminated" means one is missing.
# If we replace ALL """ with ''', it might not help if one is missing.
# If we replace ALL """ with # """, we comment them out.

new_content = content.replace('"""', '# """')

with open(file_path, 'w', encoding='utf-8') as f:
    f.write(new_content)

print(f"Patched {file_path}")
