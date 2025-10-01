import yara
import os
import json
from typing import List, Dict

YARA_DIR = r"E:\Desktop\Hacktoberfest2025-CyberSec\threatintelautomation\libs\yara"

# Compile all .yar/.yara files in the submodule dir into a single ruleset
def compile_yara_rules(yara_dir: str):
    # Use the existing index file which properly handles dependencies
    malware_index_path = os.path.join(yara_dir, "malware_index.yar")
    
    if os.path.exists(malware_index_path):
        print(f"Using existing malware index: {malware_index_path}")
        try:
            rules = yara.compile(filepath=malware_index_path)
            return rules
        except yara.SyntaxError as e:
            print(f"Syntax error in malware index: {e}")
            # Fall back to individual file compilation
    
    # Fallback: compile individual files (excluding problematic modules)
    filepaths = {}
    excluded_modules = ['androguard', 'cuckoo']  # modules not available
    
    for root, _, files in os.walk(yara_dir):
        for f in files:
            if f.endswith(('.yar', '.yara')):
                filepath = os.path.join(root, f)
                
                # Skip index files to avoid circular includes
                if 'index' in f.lower():
                    continue
                
                # Check if file imports unavailable modules
                try:
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as file:
                        content = file.read()
                        # Skip files that import unavailable modules
                        should_skip = any(f'import "{module}"' in content for module in excluded_modules)
                        if should_skip:
                            print(f"Skipping {filepath} - depends on unavailable module")
                            continue
                except Exception as e:
                    print(f"Warning: Could not read {filepath}: {e}")
                    continue
                
                key = os.path.splitext(f)[0]  # unique id per file
                # Handle duplicate filenames by adding path info
                if key in filepaths:
                    key = f"{os.path.basename(root)}_{key}"
                filepaths[key] = filepath
                
    if not filepaths:
        raise RuntimeError("No YARA files found to compile.")
    rules = yara.compile(filepaths=filepaths)
    return rules

# Structured scan function
def scan_file(rules: yara.Rules, file_path: str, timeout: int = 10) -> List[Dict]:
    try:
        matches = rules.match(filepath=file_path, timeout=timeout)
    except yara.TimeoutError:
        return [{"error": "timeout", "file": file_path}]
    except Exception as e:
        return [{"error": "exception", "message": str(e), "file": file_path}]

    results = []
    for m in matches:
        # m is a yara.Match object
        string_matches = []
        for string_match in m.strings:
            # Each string_match is a yara.StringMatch object
            string_matches.append({
                "identifier": string_match.identifier,
                "instances": [
                    {
                        "offset": instance.offset,
                        "matched_data": instance.matched_data.hex() if isinstance(instance.matched_data, bytes) else str(instance.matched_data),
                        "matched_length": instance.matched_length
                    }
                    for instance in string_match.instances
                ]
            })
        
        results.append({
            "rule": m.rule,
            "namespace": m.namespace,
            "tags": list(m.tags),
            "meta": dict(m.meta),
            "strings": string_matches
        })
    return results

if __name__ == "__main__":
    rules = compile_yara_rules(YARA_DIR)
    out = scan_file(rules, "./sample/sample", timeout=10)
    print(json.dumps(out, indent=2))
