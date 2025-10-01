import os

YARA_DIR = r"E:\Desktop\Hacktoberfest2025-CyberSec\threatintelautomation\libs\yara"
filepaths = {}
excluded_modules = ['androguard', 'cuckoo']
for root, _, files in os.walk(YARA_DIR):
    for f in files:
        if f.endswith(('.yar', '.yara')):
            filepath = os.path.join(root, f)
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as file:
                    content = file.read()
                    should_skip = any(f'import "{module}"' in content for module in excluded_modules)
                    if should_skip:
                        continue
            except:
                continue
            key = os.path.splitext(f)[0]
            if key in filepaths:
                key = f'{os.path.basename(root)}_{key}'
            filepaths[key] = filepath
            if '000_common_rules' in f:
                print(f'Found common rules: {filepath}')
print(f'Total files to compile: {len(filepaths)}')

# Check if files using is__elf are included
for key, path in filepaths.items():
    if 'MALW_Httpsd_ELF' in path:
        print(f'Found ELF file: {key} -> {path}')