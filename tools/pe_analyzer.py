#!/usr/bin/env python3
"""
Advanced PE (Portable Executable) Analyzer
Detaylı .exe dosya analizi için gelişmiş araç
"""

import os
import sys
import struct
import hashlib
import math
from datetime import datetime
from collections import Counter

class PEAnalyzer:
    def __init__(self, file_path):
        self.file_path = file_path
        self.file_data = None
        self.dos_header = None
        self.pe_header = None
        self.optional_header = None
        self.sections = []
        self.imports = []
        self.exports = []
        
    def load_file(self):
        """Dosyayı yükle"""
        try:
            with open(self.file_path, 'rb') as f:
                self.file_data = f.read()
            return True
        except Exception as e:
            print(f"Dosya yüklenemedi: {e}")
            return False
    
    def get_file_info(self):
        """Temel dosya bilgileri"""
        if not self.file_data:
            return None
            
        info = {
            'file_size': len(self.file_data),
            'md5': hashlib.md5(self.file_data).hexdigest(),
            'sha1': hashlib.sha1(self.file_data).hexdigest(),
            'sha256': hashlib.sha256(self.file_data).hexdigest()
        }
        return info
    
    def calculate_entropy(self, data):
        """Data entropy hesaplama"""
        if not data:
            return 0
        
        # Byte frekansları
        byte_counts = Counter(data)
        entropy = 0
        data_len = len(data)
        
        for count in byte_counts.values():
            probability = count / data_len
            if probability > 0:
                entropy += -probability * math.log2(probability)
                
        return entropy
    
    def parse_dos_header(self):
        """DOS header analizi"""
        if len(self.file_data) < 64:
            return False
            
        self.dos_header = {
            'signature': self.file_data[:2],
            'bytes_in_last_page': struct.unpack('<H', self.file_data[2:4])[0],
            'pages_in_file': struct.unpack('<H', self.file_data[4:6])[0],
            'relocations': struct.unpack('<H', self.file_data[6:8])[0],
            'size_of_header': struct.unpack('<H', self.file_data[8:10])[0],
            'pe_offset': struct.unpack('<I', self.file_data[60:64])[0]
        }
        return True
    
    def parse_pe_header(self):
        """PE header analizi"""
        if not self.dos_header:
            return False
            
        pe_offset = self.dos_header['pe_offset']
        if pe_offset + 24 > len(self.file_data):
            return False
            
        self.pe_header = {
            'signature': self.file_data[pe_offset:pe_offset+4],
            'machine': struct.unpack('<H', self.file_data[pe_offset+4:pe_offset+6])[0],
            'number_of_sections': struct.unpack('<H', self.file_data[pe_offset+6:pe_offset+8])[0],
            'time_date_stamp': struct.unpack('<I', self.file_data[pe_offset+8:pe_offset+12])[0],
            'characteristics': struct.unpack('<H', self.file_data[pe_offset+22:pe_offset+24])[0]
        }
        
        # Machine type decode
        machine_types = {
            0x14c: 'IMAGE_FILE_MACHINE_I386',
            0x8664: 'IMAGE_FILE_MACHINE_AMD64',
            0x1c0: 'IMAGE_FILE_MACHINE_ARM',
            0xaa64: 'IMAGE_FILE_MACHINE_ARM64'
        }
        
        self.pe_header['machine_type'] = machine_types.get(
            self.pe_header['machine'], 
            f"Unknown (0x{self.pe_header['machine']:x})"
        )
        
        return True
    
    def parse_sections(self):
        """Section header analizi"""
        if not self.pe_header:
            return False
            
        pe_offset = self.dos_header['pe_offset']
        section_table_offset = pe_offset + 24 + 224  # PE header + Optional header size
        
        self.sections = []
        for i in range(self.pe_header['number_of_sections']):
            section_offset = section_table_offset + (i * 40)
            if section_offset + 40 > len(self.file_data):
                break
                
            section_data = self.file_data[section_offset:section_offset+40]
            section = {
                'name': section_data[:8].rstrip(b'\x00').decode('ascii', errors='ignore'),
                'virtual_size': struct.unpack('<I', section_data[8:12])[0],
                'virtual_address': struct.unpack('<I', section_data[12:16])[0],
                'size_of_raw_data': struct.unpack('<I', section_data[16:20])[0],
                'pointer_to_raw_data': struct.unpack('<I', section_data[20:24])[0],
                'characteristics': struct.unpack('<I', section_data[36:40])[0]
            }
            
            # Section data entropy
            if section['pointer_to_raw_data'] and section['size_of_raw_data']:
                start = section['pointer_to_raw_data']
                end = start + section['size_of_raw_data']
                if end <= len(self.file_data):
                    section_data_content = self.file_data[start:end]
                    section['entropy'] = self.calculate_entropy(section_data_content)
            
            self.sections.append(section)
            
        return True
    
    def check_pe_signature(self):
        """PE imzasını kontrol et"""
        if not self.file_data or len(self.file_data) < 64:
            return False
        
        # DOS header kontrol
        if self.file_data[:2] != b'MZ':
            return False
        
        # PE header offset
        pe_offset = struct.unpack('<I', self.file_data[60:64])[0]
        
        # PE signature kontrol
        if pe_offset >= len(self.file_data) - 4:
            return False
            
        if self.file_data[pe_offset:pe_offset+4] != b'PE\x00\x00':
            return False
            
        return True
    
    def detect_packer(self):
        """Packer detection"""
        suspicious_sections = []
        high_entropy_sections = []
        
        for section in self.sections:
            # Yüksek entropy (>7.0) şüpheli
            if section.get('entropy', 0) > 7.0:
                high_entropy_sections.append(section['name'])
            
            # Şüpheli section isimleri
            suspicious_names = ['UPX', 'ASPack', 'FSG', '.themida', '.vmp']
            if any(sus in section['name'].upper() for sus in suspicious_names):
                suspicious_sections.append(section['name'])
        
        return {
            'suspicious_sections': suspicious_sections,
            'high_entropy_sections': high_entropy_sections,
            'packed_probability': len(high_entropy_sections) / len(self.sections) if self.sections else 0
        }
    
    def analyze(self):
        """Ana analiz fonksiyonu"""
        if not self.load_file():
            return False
        
        print(f"Dosya: {self.file_path}")
        print("=" * 80)
        
        # Dosya bilgileri
        file_info = self.get_file_info()
        if file_info:
            print(f"\n📁 DOSYA BİLGİLERİ")
            print(f"Boyut: {file_info['file_size']:,} bytes")
            print(f"MD5: {file_info['md5']}")
            print(f"SHA1: {file_info['sha1']}")
            print(f"SHA256: {file_info['sha256']}")
        
        # PE kontrolü
        if not self.check_pe_signature():
            print("\n❌ Geçersiz PE dosyası")
            return False
            
        print("\n✅ Geçerli PE dosyası")
        
        # DOS Header
        if self.parse_dos_header():
            print(f"\n📋 DOS HEADER")
            print(f"PE Offset: 0x{self.dos_header['pe_offset']:x}")
            print(f"Relocations: {self.dos_header['relocations']}")
        
        # PE Header
        if self.parse_pe_header():
            print(f"\n🔧 PE HEADER")
            print(f"Machine: {self.pe_header['machine_type']}")
            print(f"Sections: {self.pe_header['number_of_sections']}")
            print(f"Timestamp: {datetime.fromtimestamp(self.pe_header['time_date_stamp'])}")
            print(f"Characteristics: 0x{self.pe_header['characteristics']:x}")
        
        # Sections
        if self.parse_sections():
            print(f"\n📊 SECTIONS ({len(self.sections)} adet)")
            print(f"{'Name':<12} {'VirtSize':<10} {'VirtAddr':<10} {'RawSize':<10} {'Entropy':<8} {'Flags'}")
            print("-" * 70)
            for section in self.sections:
                entropy = section.get('entropy', 0)
                entropy_str = f"{entropy:.2f}" if entropy else "N/A"
                print(f"{section['name']:<12} {section['virtual_size']:<10} "
                      f"0x{section['virtual_address']:08x} {section['size_of_raw_data']:<10} "
                      f"{entropy_str:<8} 0x{section['characteristics']:08x}")
        
        # Packer Detection
        packer_info = self.detect_packer()
        print(f"\n🔍 PACKER DETECTION")
        print(f"Packed Probability: {packer_info['packed_probability']:.2%}")
        if packer_info['suspicious_sections']:
            print(f"Suspicious Sections: {', '.join(packer_info['suspicious_sections'])}")
        if packer_info['high_entropy_sections']:
            print(f"High Entropy Sections: {', '.join(packer_info['high_entropy_sections'])}")
        
        # Overall entropy
        overall_entropy = self.calculate_entropy(self.file_data)
        print(f"\n📈 ENTROPY ANALİZİ")
        print(f"Overall Entropy: {overall_entropy:.2f}")
        if overall_entropy > 7.5:
            print("⚠️  Yüksek entropy - Muhtemelen packed/encrypted")
        elif overall_entropy > 6.0:
            print("⚠️  Orta seviye entropy - Şüpheli olabilir")
        else:
            print("✅ Normal entropy seviyesi")
        
        return True

def main():
    if len(sys.argv) != 2:
        print("Kullanım: python pe_analyzer.py <exe_dosyasi>")
        sys.exit(1)
    
    file_path = sys.argv[1]
    if not os.path.exists(file_path):
        print(f"Dosya bulunamadı: {file_path}")
        sys.exit(1)
    
    analyzer = PEAnalyzer(file_path)
    analyzer.analyze()

if __name__ == "__main__":
    main()