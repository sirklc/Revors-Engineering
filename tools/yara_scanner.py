#!/usr/bin/env python3
"""
YARA Rules Scanner
YARA kuralları ile malware detection
"""

import sys
import os
import re

class YaraScanner:
    def __init__(self, file_path):
        self.file_path = file_path
        self.file_data = None
        self.rules_dir = "rules"
        
    def load_file(self):
        """Dosyayı yükle"""
        try:
            with open(self.file_path, 'rb') as f:
                self.file_data = f.read()
            return True
        except Exception as e:
            print(f"Dosya yüklenemedi: {e}")
            return False
    
    def create_basic_rules(self):
        """Temel YARA kurallarını oluştur"""
        if not os.path.exists(self.rules_dir):
            os.makedirs(self.rules_dir)
        
        # UPX Packer Rule
        upx_rule = '''rule UPX_Packer
{
    meta:
        description = "UPX Packer Detection"
        author = "RE Tool"
        
    strings:
        $upx1 = "UPX!"
        $upx2 = "UPX0"
        $upx3 = "UPX1"
        
    condition:
        any of ($upx*)
}'''

        # Suspicious API Rule
        api_rule = '''rule Suspicious_APIs
{
    meta:
        description = "Suspicious API Calls"
        author = "RE Tool"
        
    strings:
        $api1 = "CreateRemoteThread"
        $api2 = "VirtualAlloc"
        $api3 = "WriteProcessMemory"
        $api4 = "IsDebuggerPresent"
        $api5 = "RegSetValue"
        
    condition:
        2 of ($api*)
}'''

        # Crypto Strings Rule
        crypto_rule = '''rule Crypto_Strings
{
    meta:
        description = "Cryptographic Strings"
        author = "RE Tool"
        
    strings:
        $crypto1 = "CryptAcquireContext"
        $crypto2 = "CryptEncrypt"
        $crypto3 = "CryptDecrypt"
        $crypto4 = "CryptGenKey"
        
    condition:
        any of ($crypto*)
}'''

        # PE Anomaly Rule
        pe_rule = '''rule PE_Anomaly
{
    meta:
        description = "PE Structure Anomalies"
        author = "RE Tool"
        
    strings:
        $mz = { 4D 5A }
        $pe = "PE"
        
    condition:
        $mz at 0 and not $pe
}'''

        rules = [
            ("upx_detection.yar", upx_rule),
            ("suspicious_apis.yar", api_rule),
            ("crypto_detection.yar", crypto_rule),
            ("pe_anomaly.yar", pe_rule)
        ]
        
        for filename, content in rules:
            rule_path = os.path.join(self.rules_dir, filename)
            if not os.path.exists(rule_path):
                with open(rule_path, 'w') as f:
                    f.write(content)
    
    def parse_yara_rule(self, rule_content):
        """YARA kuralını basit olarak parse et"""
        rule_name = re.search(r'rule\s+(\w+)', rule_content)
        if not rule_name:
            return None
            
        strings_section = re.search(r'strings:\s*(.*?)\s*condition:', rule_content, re.DOTALL)
        condition_section = re.search(r'condition:\s*(.*?)(?=\}$)', rule_content, re.DOTALL)
        
        if not strings_section or not condition_section:
            return None
            
        # Parse strings
        strings = {}
        for match in re.finditer(r'\$(\w+)\s*=\s*"([^"]+)"', strings_section.group(1)):
            strings[match.group(1)] = match.group(2).encode('ascii', errors='ignore')
            
        # Parse hex strings
        for match in re.finditer(r'\$(\w+)\s*=\s*\{\s*([^}]+)\s*\}', strings_section.group(1)):
            hex_bytes = re.findall(r'[0-9A-Fa-f]{2}', match.group(2))
            strings[match.group(1)] = bytes.fromhex(''.join(hex_bytes))
        
        return {
            'name': rule_name.group(1),
            'strings': strings,
            'condition': condition_section.group(1).strip()
        }
    
    def evaluate_condition(self, condition, matches):
        """Basit condition evaluation"""
        # "any of ($string*)" pattern
        any_match = re.search(r'any of \(\$(\w+)\*\)', condition)
        if any_match:
            prefix = any_match.group(1)
            return any(key.startswith(prefix) for key in matches)
        
        # "X of ($string*)" pattern  
        count_match = re.search(r'(\d+) of \(\$(\w+)\*\)', condition)
        if count_match:
            required_count = int(count_match.group(1))
            prefix = count_match.group(2)
            actual_count = sum(1 for key in matches if key.startswith(prefix))
            return actual_count >= required_count
        
        # "any of them" pattern
        if 'any of them' in condition:
            return len(matches) > 0
            
        # "$string" pattern
        string_match = re.search(r'\$(\w+)', condition)
        if string_match:
            return string_match.group(1) in matches
            
        return False
    
    def scan_with_rule(self, rule):
        """Dosyayı bir kuralla tarama"""
        matches = {}
        
        for string_name, pattern in rule['strings'].items():
            if pattern in self.file_data:
                matches[string_name] = True
                
        # Condition evaluation
        if self.evaluate_condition(rule['condition'], matches):
            return {
                'rule_name': rule['name'],
                'matches': list(matches.keys())
            }
            
        return None
    
    def scan_all_rules(self):
        """Tüm kurallarla tarama"""
        self.create_basic_rules()
        results = []
        
        if not os.path.exists(self.rules_dir):
            print(f"Rules dizini bulunamadı: {self.rules_dir}")
            return results
            
        for rule_file in os.listdir(self.rules_dir):
            if not rule_file.endswith('.yar'):
                continue
                
            rule_path = os.path.join(self.rules_dir, rule_file)
            try:
                with open(rule_path, 'r') as f:
                    rule_content = f.read()
                    
                rule = self.parse_yara_rule(rule_content)
                if rule:
                    result = self.scan_with_rule(rule)
                    if result:
                        results.append(result)
                        
            except Exception as e:
                print(f"Kural dosyası okunamadı {rule_file}: {e}")
                
        return results
    
    def analyze(self):
        """Ana analiz fonksiyonu"""
        if not self.load_file():
            return False
            
        print(f"🔍 YARA TARAMASI: {os.path.basename(self.file_path)}")
        print("=" * 80)
        
        results = self.scan_all_rules()
        
        if results:
            print(f"\n⚠️  TESPIT EDİLEN KURALLAR ({len(results)} adet)")
            print("-" * 40)
            
            for result in results:
                print(f"\n🎯 {result['rule_name']}")
                print(f"   Matches: {', '.join(result['matches'])}")
        else:
            print(f"\n✅ Hiçbir kural tetiklenmedi")
        
        print(f"\nTarama tamamlandı. Toplam {len(os.listdir(self.rules_dir))} kural kontrol edildi.")
        return True

def main():
    if len(sys.argv) != 2:
        print("Kullanım: python yara_scanner.py <exe_dosyasi>")
        sys.exit(1)
    
    file_path = sys.argv[1]
    if not os.path.exists(file_path):
        print(f"Dosya bulunamadı: {file_path}")
        sys.exit(1)
    
    scanner = YaraScanner(file_path)
    scanner.analyze()

if __name__ == "__main__":
    main()