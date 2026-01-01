import os

file_path = r"c:\Users\khanj\Matrix\backend\agents\github_agent.py"

with open(file_path, 'r', encoding='utf-8') as f:
    lines = f.readlines()

output_lines = []
skip = False
found_sbom = False

for i, line in enumerate(lines):
    # Start skipping at the SECOND occurrence of _scan_dependencies (the garbage one)
    # We know the first one is valid.
    # Actually, simpler: Skip from line 1202 until we see 'def generate_sbom'
    
    if i < 1202:
        output_lines.append(line)
        continue
        
    if "def generate_sbom" in line:
        skip = False
        found_sbom = True
        
    if not skip and found_sbom:
        output_lines.append(line)
    elif not skip and not found_sbom:
        # We are in the gap (1202 to generate_sbom). 
        # But wait, we want to INSERT _log_scan_statistics here if it's missing.
        # Check if _log_scan_statistics is in the valid part.
        pass

# Add _log_scan_statistics manually if needed
# But for now, let's just clean the file.
# Note: I need to verify if _log_scan_statistics is in the output.
# It likely isn't because it was in the garbage block.
# So I will append it before generate_sbom?
# Actually, let's just delete the garbage first.

print(f"Kept {len(output_lines)} lines.")

# Insert _log_scan_statistics before generate_sbom
# Find index of generate_sbom in output_lines
idx = -1
for i, line in enumerate(output_lines):
    if "def generate_sbom" in line:
        idx = i
        break

if idx != -1:
    log_stats_code = [
        "\n",
        "    def _log_scan_statistics(self, owner: str, repo: str) -> None:\n",
        "        # Log scanning statistics\n",
        "        cache_hit_rate = 0.0\n",
        "        total_cache_ops = self.stats['cache_hits'] + self.stats['cache_misses']\n",
        "        if total_cache_ops > 0:\n",
        "            cache_hit_rate = (self.stats['cache_hits'] / total_cache_ops) * 100\n",
        "\n",
        "        logger.info(f\"GitHub Scan Stats for {owner}/{repo}: \"\n",
        "                   f\"Files={self.stats['files_scanned']}, \"\n",
        "                   f\"Secrets={self.stats['secrets_found']}, \"\n",
        "                   f\"Cache Hit Rate={cache_hit_rate:.1f}%\")\n",
        "\n"
    ]
    output_lines[idx:idx] = log_stats_code
    print("Inserted _log_scan_statistics.")

with open(file_path, 'w', encoding='utf-8') as f:
    f.writelines(output_lines)
print("File cleaned successfully.")
