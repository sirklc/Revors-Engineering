#!/usr/bin/env python3
"""
Import/Export Table Analyzer
PE dosyalarındaki import ve export tabloları analizi
"""

import sys
import struct
import os

class ImportExportAnalyzer:
    def __init__(self, file_path):
        self.file_path = file_path
        self.file_data = None
        self.pe_offset = None
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
    
    def get_pe_offset(self):
        """PE header offset'ini al"""
        if len(self.file_data) < 64:
            return False
        self.pe_offset = struct.unpack('<I', self.file_data[60:64])[0]
        return True
    
    def parse_imports(self):
        """Import tablosunu parse et"""
        if not self.pe_offset:
            return False
            
        # Optional header'dan import table RVA'sını al
        opt_header_offset = self.pe_offset + 24
        if opt_header_offset + 96 > len(self.file_data):
            return False
            
        import_table_rva = struct.unpack('<I', self.file_data[opt_header_offset + 96:opt_header_offset + 100])[0]
        import_table_size = struct.unpack('<I', self.file_data[opt_header_offset + 100:opt_header_offset + 104])[0]
        
        if import_table_rva == 0:
            return True  # No imports
            
        # RVA to file offset conversion (simplified)
        import_table_offset = self.rva_to_offset(import_table_rva)
        if not import_table_offset:
            return False
            
        # Parse import descriptors
        offset = import_table_offset
        while offset + 20 <= len(self.file_data):
            descriptor = self.file_data[offset:offset + 20]
            
            # Check for null descriptor (end of table)
            if descriptor == b'\x00' * 20:
                break
                
            import_lookup_rva = struct.unpack('<I', descriptor[0:4])[0]
            name_rva = struct.unpack('<I', descriptor[12:16])[0]
            import_address_rva = struct.unpack('<I', descriptor[16:20])[0]
            
            if name_rva == 0:
                break
                
            # Get DLL name
            name_offset = self.rva_to_offset(name_rva)
            if name_offset:
                dll_name = self.read_cstring(name_offset)
                
                # Parse functions
                functions = self.parse_import_functions(import_lookup_rva or import_address_rva)
                
                self.imports.append({
                    'dll': dll_name,
                    'functions': functions
                })
            
            offset += 20
            
        return True
    
    def parse_import_functions(self, rva):
        """Import edilen fonksiyonları parse et"""
        functions = []
        if not rva:
            return functions
            
        offset = self.rva_to_offset(rva)
        if not offset:
            return functions
            
        # 32-bit veya 64-bit kontrol (basitleştirilmiş)
        ptr_size = 4  # 32-bit varsayımı
        
        while offset + ptr_size <= len(self.file_data):
            if ptr_size == 4:
                func_rva = struct.unpack('<I', self.file_data[offset:offset + 4])[0]
            else:
                func_rva = struct.unpack('<Q', self.file_data[offset:offset + 8])[0]
                
            if func_rva == 0:
                break
                
            # Ordinal mı yoksa name mi?
            if func_rva & 0x80000000:  # Ordinal
                ordinal = func_rva & 0xFFFF
                functions.append(f"Ordinal_{ordinal}")
            else:  # Name
                name_offset = self.rva_to_offset(func_rva)
                if name_offset and name_offset + 2 < len(self.file_data):
                    # Skip hint (2 bytes)
                    func_name = self.read_cstring(name_offset + 2)
                    functions.append(func_name)
                    
            offset += ptr_size
            
        return functions
    
    def rva_to_offset(self, rva):
        """RVA'yı file offset'e çevir (basitleştirilmiş)"""
        # Section table'ı parse et
        section_count = struct.unpack('<H', self.file_data[self.pe_offset + 6:self.pe_offset + 8])[0]
        section_table_offset = self.pe_offset + 24 + 224  # PE + Optional header
        
        for i in range(section_count):
            section_offset = section_table_offset + (i * 40)
            if section_offset + 40 > len(self.file_data):
                break
                
            virtual_address = struct.unpack('<I', self.file_data[section_offset + 12:section_offset + 16])[0]
            virtual_size = struct.unpack('<I', self.file_data[section_offset + 8:section_offset + 12])[0]
            raw_address = struct.unpack('<I', self.file_data[section_offset + 20:section_offset + 24])[0]
            
            if virtual_address <= rva < virtual_address + virtual_size:
                return raw_address + (rva - virtual_address)
                
        return None
    
    def read_cstring(self, offset):
        """Null-terminated string oku"""
        if offset >= len(self.file_data):
            return ""
            
        end = offset
        while end < len(self.file_data) and self.file_data[end] != 0:
            end += 1
            
        return self.file_data[offset:end].decode('ascii', errors='ignore')
    
    def analyze_suspicious_imports(self):
        """Şüpheli import'ları analiz et"""
        suspicious_apis = {
            'Process': ['CreateProcess', 'OpenProcess', 'TerminateProcess'],
            'Registry': ['RegOpenKey', 'RegSetValue', 'RegDeleteKey'],
            'File': ['CreateFile', 'DeleteFile', 'MoveFile'],
            'Network': ['socket', 'connect', 'send', 'recv', 'WSAStartup'],
            'Crypto': ['CryptAcquireContext', 'CryptEncrypt', 'CryptDecrypt'],
            'Debug': ['IsDebuggerPresent', 'CheckRemoteDebuggerPresent'],
            'Injection': ['VirtualAlloc', 'WriteProcessMemory', 'CreateRemoteThread'],
            'Privilege': ['AdjustTokenPrivileges', 'LookupPrivilegeValue']
        }
        
        findings = {}
        for dll_info in self.imports:
            dll_name = dll_info['dll'].lower()
            functions = dll_info['functions']
            
            for category, api_list in suspicious_apis.items():
                matches = [func for func in functions if any(api.lower() in func.lower() for api in api_list)]
                if matches:
                    if category not in findings:
                        findings[category] = []
                    findings[category].extend([(dll_name, func) for func in matches])
                    
        return findings
    
    def analyze(self):
        """Ana analiz fonksiyonu"""
        if not self.load_file():
            return False
            
        if not self.get_pe_offset():
            print("❌ PE offset bulunamadı")
            return False
            
        print(f"📦 IMPORT/EXPORT ANALİZİ: {os.path.basename(self.file_path)}")
        print("=" * 80)
        
        # Import analizi
        if self.parse_imports():
            print(f"\n📥 IMPORTS ({len(self.imports)} DLL)")
            print("-" * 50)
            
            total_functions = 0
            for dll_info in self.imports:
                func_count = len(dll_info['functions'])
                total_functions += func_count
                print(f"\n{dll_info['dll']} ({func_count} fonksiyon)")
                
                # İlk 10 fonksiyonu göster
                for func in dll_info['functions'][:10]:
                    print(f"  └─ {func}")
                    
                if len(dll_info['functions']) > 10:
                    print(f"  └─ ... ve {len(dll_info['functions']) - 10} tane daha")
            
            print(f"\nToplam: {total_functions} import fonksiyonu")
            
            # Şüpheli API analizi
            suspicious = self.analyze_suspicious_imports()
            if suspicious:
                print(f"\n⚠️  ŞÜPHELİ API ÇAĞRILARI")
                print("-" * 30)
                for category, apis in suspicious.items():
                    print(f"\n{category}:")
                    for dll, func in apis:
                        print(f"  {dll} -> {func}")
            else:
                print(f"\n✅ Şüpheli API bulunamadı")
        
        return True

def main():
    if len(sys.argv) != 2:
        print("Kullanım: python import_analyzer.py <exe_dosyasi>")
        sys.exit(1)
    
    file_path = sys.argv[1]
    if not os.path.exists(file_path):
        print(f"Dosya bulunamadı: {file_path}")
        sys.exit(1)
    
    analyzer = ImportExportAnalyzer(file_path)
    analyzer.analyze()

if __name__ == "__main__":
    main()