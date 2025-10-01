import yara

rules = yara.compile(filepath='E:/Desktop/Hacktoberfest2025-CyberSec/threatintelautomation/libs/yara/malware_index.yar')
def scan_file(file_path):
    matches = rules.match(file_path)
    return matches
scan_file('./sample/sample')