#!/usr/bin/env python3
"""
Memory Dump Analyzer
Memory dump dosyalarını analiz etme ve PE dosyalarından memory layout çıkarma
"""

import sys
import os
import struct
import re
from collections import defaultdict

class MemoryDumpAnalyzer:
    def __init__(self, file_path, output_dir="extracted/dumps"):
        self.file_path = file_path
        self.output_dir = output_dir
        self.file_data = None
        self.pe_offset = None
        self.memory_regions = []
        self.embedded_pes = []
        self.suspicious_patterns = []
        
        os.makedirs(output_dir, exist_ok=True)
        
    def load_file(self):
        """Dosyayı yükle"""
        try:
            with open(self.file_path, 'rb') as f:
                self.file_data = f.read()
            return True
        except Exception as e:
            print(f"Dosya yüklenemedi: {e}")
            return False
    
    def scan_for_pe_headers(self):
        """Dosya içinde PE header'ları ara"""
        pe_headers = []
        
        # MZ signature ara
        mz_positions = []
        offset = 0
        while True:
            pos = self.file_data.find(b'MZ', offset)
            if pos == -1:
                break
            mz_positions.append(pos)
            offset = pos + 1
        
        print(f"🔍 {len(mz_positions)} adet MZ signature bulundu")
        
        # Her MZ position için PE signature kontrol et
        for mz_pos in mz_positions:
            if mz_pos + 64 > len(self.file_data):
                continue
                
            try:
                pe_offset = struct.unpack('<I', self.file_data[mz_pos + 60:mz_pos + 64])[0]
                pe_pos = mz_pos + pe_offset
                
                if pe_pos + 4 <= len(self.file_data):
                    if self.file_data[pe_pos:pe_pos + 4] == b'PE\x00\x00':
                        pe_headers.append({
                            'mz_offset': mz_pos,
                            'pe_offset': pe_pos,
                            'pe_relative_offset': pe_offset
                        })
            except:
                continue
        
        return pe_headers
    
    def extract_embedded_pe(self, pe_info):
        """Embedded PE dosyasını çıkar"""
        mz_offset = pe_info['mz_offset']
        pe_offset = pe_info['pe_offset']
        
        try:
            # PE header'ı parse et
            machine = struct.unpack('<H', self.file_data[pe_offset + 4:pe_offset + 6])[0]
            num_sections = struct.unpack('<H', self.file_data[pe_offset + 6:pe_offset + 8])[0]
            
            # Optional header size
            opt_header_size = struct.unpack('<H', self.file_data[pe_offset + 20:pe_offset + 22])[0]
            
            # Section table offset
            section_table_offset = pe_offset + 24 + opt_header_size
            
            # Son section'ın sonunu bul
            max_end_offset = mz_offset
            
            for i in range(num_sections):
                section_offset = section_table_offset + (i * 40)
                if section_offset + 40 > len(self.file_data):
                    break
                
                raw_address = struct.unpack('<I', self.file_data[section_offset + 20:section_offset + 24])[0]
                raw_size = struct.unpack('<I', self.file_data[section_offset + 16:section_offset + 20])[0]
                
                if raw_address > 0 and raw_size > 0:
                    section_end = mz_offset + raw_address + raw_size
                    max_end_offset = max(max_end_offset, section_end)
            
            # PE dosyasını çıkar
            if max_end_offset > mz_offset and max_end_offset <= len(self.file_data):
                pe_data = self.file_data[mz_offset:max_end_offset]
                
                return {
                    'offset': mz_offset,
                    'size': len(pe_data),
                    'data': pe_data,
                    'machine': machine,
                    'sections': num_sections,
                    'valid': True
                }
        except Exception as e:
            return {
                'offset': mz_offset,
                'size': 0,
                'data': None,
                'error': str(e),
                'valid': False
            }
        
        return None
    
    def scan_for_strings_patterns(self):
        """Şüpheli string pattern'ları ara"""
        patterns = {
            'urls': rb'https?://[^\s<>"\']+',
            'file_paths': rb'[A-Za-z]:\\[^\\/:*?"<>|\\r\\n]+',
            'registry_keys': rb'HKEY_[A-Z_]+\\[^\\r\\n]+',
            'ip_addresses': rb'\\b(?:[0-9]{1,3}\\.){3}[0-9]{1,3}\\b',
            'email_addresses': rb'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}',
            'crypto_constants': rb'(MD5|SHA1|SHA256|AES|DES|RSA|base64)',
            'suspicious_apis': rb'(CreateProcess|WriteProcessMemory|VirtualAlloc|RegSetValue)',
            'malware_families': rb'(trojan|virus|malware|backdoor|keylogger|ransomware)'
        }
        
        findings = defaultdict(list)
        
        for pattern_name, pattern in patterns.items():
            matches = re.finditer(pattern, self.file_data, re.IGNORECASE)
            for match in matches:
                findings[pattern_name].append({
                    'offset': match.start(),
                    'data': match.group().decode('ascii', errors='ignore'),
                    'length': len(match.group())
                })
        
        return findings
    
    def analyze_memory_regions(self):
        """Memory region'ları analiz et"""
        regions = []
        
        # Entropy tabanlı region segmentasyonu
        chunk_size = 4096  # 4KB chunks
        
        for offset in range(0, len(self.file_data), chunk_size):
            chunk = self.file_data[offset:offset + chunk_size]
            if len(chunk) < 100:  # Çok küçük chunk'ları skip et
                continue
            
            # Entropy hesapla
            entropy = self.calculate_entropy(chunk)
            
            # Null byte ratio
            null_ratio = chunk.count(0) / len(chunk)
            
            # ASCII ratio
            ascii_count = sum(1 for b in chunk if 32 <= b <= 126)
            ascii_ratio = ascii_count / len(chunk)
            
            region = {
                'offset': offset,
                'size': len(chunk),
                'entropy': entropy,
                'null_ratio': null_ratio,
                'ascii_ratio': ascii_ratio,
                'type': self.classify_region(entropy, null_ratio, ascii_ratio)
            }
            
            regions.append(region)
        
        return regions
    
    def calculate_entropy(self, data):
        """Shannon entropy hesapla"""
        if not data:
            return 0
        
        from collections import Counter
        import math
        
        byte_counts = Counter(data)
        entropy = 0
        data_len = len(data)
        
        for count in byte_counts.values():
            probability = count / data_len
            if probability > 0:
                entropy += -probability * math.log2(probability)
        
        return entropy
    
    def classify_region(self, entropy, null_ratio, ascii_ratio):
        """Memory region tipini sınıflandır"""
        if null_ratio > 0.8:
            return "EMPTY/PADDING"
        elif entropy > 7.5:
            return "ENCRYPTED/PACKED"
        elif entropy < 2.0:
            return "REPETITIVE/PATTERN"
        elif ascii_ratio > 0.7:
            return "TEXT/STRINGS"
        elif 4.0 <= entropy <= 6.0:
            return "CODE/EXECUTABLE"
        else:
            return "DATA/BINARY"
    
    def create_memory_map(self):
        """Memory map oluştur"""
        file_base = os.path.splitext(os.path.basename(self.file_path))[0]
        map_file = os.path.join(self.output_dir, f"{file_base}_memory_map.txt")
        
        with open(map_file, 'w') as f:
            f.write(f"Memory Map Analysis: {self.file_path}\\n")
            f.write("=" * 80 + "\\n\\n")
            
            # PE Headers
            if self.embedded_pes:
                f.write("EMBEDDED PE FILES:\\n")
                f.write("-" * 30 + "\\n")
                for i, pe in enumerate(self.embedded_pes):
                    f.write(f"PE #{i+1}:\\n")
                    f.write(f"  Offset: 0x{pe['offset']:08x}\\n")
                    f.write(f"  Size: {pe['size']:,} bytes\\n")
                    f.write(f"  Machine: 0x{pe.get('machine', 0):04x}\\n")
                    f.write(f"  Sections: {pe.get('sections', 0)}\\n")
                    f.write(f"  Valid: {pe['valid']}\\n")
                    if pe.get('error'):
                        f.write(f"  Error: {pe['error']}\\n")
                    f.write("\\n")
            
            # Memory Regions
            f.write("MEMORY REGIONS:\\n")
            f.write("-" * 30 + "\\n")
            f.write(f"{'Offset':<12} {'Size':<10} {'Type':<18} {'Entropy':<8} {'ASCII%':<8} {'Null%'}\\n")
            f.write("-" * 70 + "\\n")
            
            for region in self.memory_regions:
                f.write(f"0x{region['offset']:08x} "
                       f"{region['size']:<10} "
                       f"{region['type']:<18} "
                       f"{region['entropy']:<8.2f} "
                       f"{region['ascii_ratio']:<8.2%} "
                       f"{region['null_ratio']:.2%}\\n")
        
        return map_file
    
    def extract_suspicious_data(self, patterns):
        """Şüpheli data'ları extract et"""
        file_base = os.path.splitext(os.path.basename(self.file_path))[0]
        
        for pattern_name, matches in patterns.items():
            if not matches:
                continue
                
            pattern_file = os.path.join(self.output_dir, f"{file_base}_{pattern_name}.txt")
            with open(pattern_file, 'w') as f:
                f.write(f"{pattern_name.upper()} FINDINGS\\n")
                f.write("=" * 50 + "\\n\\n")
                
                for match in matches[:100]:  # İlk 100 match
                    f.write(f"Offset: 0x{match['offset']:08x}\\n")
                    f.write(f"Data: {match['data']}\\n")
                    f.write(f"Length: {match['length']} bytes\\n")
                    f.write("-" * 30 + "\\n")
    
    def analyze(self):
        """Ana analiz fonksiyonu"""
        if not self.load_file():
            return False
            
        print(f"💾 MEMORY DUMP ANALYSIS: {os.path.basename(self.file_path)}")
        print("=" * 80)
        
        file_base = os.path.splitext(os.path.basename(self.file_path))[0]
        
        # PE header tarama
        print("🔍 PE header taraması...")
        pe_headers = self.scan_for_pe_headers()
        
        if pe_headers:
            print(f"✅ {len(pe_headers)} adet PE dosyası bulundu")
            
            for i, pe_header in enumerate(pe_headers):
                embedded_pe = self.extract_embedded_pe(pe_header)
                if embedded_pe and embedded_pe['valid']:
                    self.embedded_pes.append(embedded_pe)
                    
                    # PE dosyasını kaydet
                    pe_file = os.path.join(self.output_dir, f"{file_base}_embedded_{i+1}.exe")
                    with open(pe_file, 'wb') as f:
                        f.write(embedded_pe['data'])
                    
                    print(f"   📄 PE #{i+1} kaydedildi: {pe_file}")
                    print(f"      Offset: 0x{embedded_pe['offset']:08x}")
                    print(f"      Size: {embedded_pe['size']:,} bytes")
        else:
            print("❌ PE dosyası bulunamadı")
        
        # Memory region analizi
        print("\\n🗺️  Memory region analizi...")
        self.memory_regions = self.analyze_memory_regions()
        
        region_types = defaultdict(int)
        for region in self.memory_regions:
            region_types[region['type']] += 1
        
        print("   Region tipleri:")
        for region_type, count in region_types.items():
            print(f"     {region_type}: {count} region")
        
        # String pattern tarama
        print("\\n🔎 Şüpheli pattern tarama...")
        patterns = self.scan_for_strings_patterns()
        
        total_findings = sum(len(matches) for matches in patterns.values())
        print(f"   Toplam {total_findings} finding bulundu:")
        
        for pattern_name, matches in patterns.items():
            if matches:
                print(f"     {pattern_name}: {len(matches)} adet")
        
        # Memory map oluştur
        print("\\n📊 Memory map oluşturuluyor...")
        map_file = self.create_memory_map()
        print(f"   Memory map: {map_file}")
        
        # Şüpheli data extract et
        if total_findings > 0:
            print("\\n💾 Şüpheli data extraction...")
            self.extract_suspicious_data(patterns)
            print("   Pattern dosyaları oluşturuldu")
        
        # Hexdump örnekleri
        print("\\n🔢 Hexdump örnekleri...")
        for i, pe in enumerate(self.embedded_pes):
            if i >= 3:  # İlk 3 PE için
                break
            hexdump_file = os.path.join(self.output_dir, f"{file_base}_pe_{i+1}_hexdump.txt")
            with open(hexdump_file, 'w') as f:
                f.write(f"Hexdump of embedded PE #{i+1}\\n")
                f.write(f"Offset: 0x{pe['offset']:08x}\\n")
                f.write("=" * 50 + "\\n\\n")
                
                # İlk 512 byte'ı hexdump olarak yaz
                for j in range(0, min(512, len(pe['data'])), 16):
                    line_data = pe['data'][j:j+16]
                    hex_part = ' '.join(f'{b:02x}' for b in line_data)
                    ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in line_data)
                    f.write(f"{j:08x}: {hex_part:<48} |{ascii_part}|\\n")
        
        print(f"\\n✅ Memory dump analizi tamamlandı!")
        print(f"📂 Çıktı dizini: {self.output_dir}")
        return True

def main():
    if len(sys.argv) < 2:
        print("Kullanım: python memory_dump_analyzer.py <dump_dosyasi> [output_dir]")
        print("\\nDesteklenen formatlar:")
        print("  - Memory dump files (.dmp, .mem)")
        print("  - PE files with embedded executables")
        print("  - Raw binary dumps")
        sys.exit(1)
    
    file_path = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else "extracted/dumps"
    
    if not os.path.exists(file_path):
        print(f"Dosya bulunamadı: {file_path}")
        sys.exit(1)
    
    analyzer = MemoryDumpAnalyzer(file_path, output_dir)
    analyzer.analyze()

if __name__ == "__main__":
    main()