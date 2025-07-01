#!/usr/bin/env python3
"""
String Extractor
Binary dosyalardan okunabilir stringleri çıkarır
"""

import sys
import re
import os

class StringExtractor:
    def __init__(self, file_path, min_length=4):
        self.file_path = file_path
        self.min_length = min_length
        
    def extract_ascii_strings(self, data):
        """ASCII stringleri çıkar"""
        pattern = b'[!-~]{' + str(self.min_length).encode() + b',}'
        matches = re.findall(pattern, data)
        return [match.decode('ascii', errors='ignore') for match in matches]
    
    def extract_unicode_strings(self, data):
        """Unicode stringleri çıkar"""
        unicode_strings = []
        i = 0
        current_string = ""
        
        while i < len(data) - 1:
            if data[i] != 0 and data[i+1] == 0:  # ASCII karakterin ardından null byte
                current_string += chr(data[i])
            elif data[i] == 0 and data[i+1] == 0:  # String sonu
                if len(current_string) >= self.min_length:
                    unicode_strings.append(current_string)
                current_string = ""
            else:
                if current_string and len(current_string) >= self.min_length:
                    unicode_strings.append(current_string)
                current_string = ""
            i += 2
            
        return unicode_strings
    
    def analyze(self):
        """String analizi yap"""
        try:
            with open(self.file_path, 'rb') as f:
                data = f.read()
        except Exception as e:
            print(f"Dosya okunamadı: {e}")
            return False
        
        print(f"Dosya: {self.file_path}")
        print("=" * 50)
        
        # ASCII stringler
        ascii_strings = self.extract_ascii_strings(data)
        print(f"\nASCII Stringler ({len(ascii_strings)} adet):")
        print("-" * 30)
        for s in ascii_strings[:50]:  # İlk 50 string
            print(f"  {s}")
        
        if len(ascii_strings) > 50:
            print(f"  ... ve {len(ascii_strings) - 50} tane daha")
        
        # Unicode stringler
        unicode_strings = self.extract_unicode_strings(data)
        print(f"\nUnicode Stringler ({len(unicode_strings)} adet):")
        print("-" * 30)
        for s in unicode_strings[:50]:  # İlk 50 string
            print(f"  {s}")
            
        if len(unicode_strings) > 50:
            print(f"  ... ve {len(unicode_strings) - 50} tane daha")
        
        return True

def main():
    if len(sys.argv) < 2:
        print("Kullanım: python strings_extractor.py <dosya> [min_uzunluk]")
        sys.exit(1)
    
    file_path = sys.argv[1]
    min_length = int(sys.argv[2]) if len(sys.argv) > 2 else 4
    
    if not os.path.exists(file_path):
        print(f"Dosya bulunamadı: {file_path}")
        sys.exit(1)
    
    extractor = StringExtractor(file_path, min_length)
    extractor.analyze()

if __name__ == "__main__":
    main()