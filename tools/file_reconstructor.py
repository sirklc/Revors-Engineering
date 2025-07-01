#!/usr/bin/env python3
"""
File Structure Reconstructor
PE dosyalarının orijinal dizin yapısını yeniden oluşturma ve unpacking
"""

import sys
import os
import struct
import shutil
from pathlib import Path
import hashlib

class FileReconstructor:
    def __init__(self, file_path, output_dir="extracted/reconstructed"):
        self.file_path = file_path
        self.output_dir = output_dir
        self.file_data = None
        self.pe_offset = None
        self.sections = []
        self.imports = []
        self.resources = []
        self.project_structure = {}
        
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
    
    def parse_pe_structure(self):
        """PE yapısını detaylı parse et"""
        if len(self.file_data) < 64:
            return False
            
        if self.file_data[:2] != b'MZ':
            return False
            
        self.pe_offset = struct.unpack('<I', self.file_data[60:64])[0]
        
        if self.file_data[self.pe_offset:self.pe_offset+4] != b'PE\x00\x00':
            return False
        
        # Section parsing
        section_count = struct.unpack('<H', self.file_data[self.pe_offset + 6:self.pe_offset + 8])[0]
        section_table_offset = self.pe_offset + 24 + 224
        
        for i in range(section_count):
            section_offset = section_table_offset + (i * 40)
            if section_offset + 40 > len(self.file_data):
                break
                
            section_data = self.file_data[section_offset:section_offset+40]
            section = {
                'name': section_data[:8].rstrip(b'\\x00').decode('ascii', errors='ignore'),
                'virtual_size': struct.unpack('<I', section_data[8:12])[0],
                'virtual_address': struct.unpack('<I', section_data[12:16])[0],
                'size_of_raw_data': struct.unpack('<I', section_data[16:20])[0],
                'pointer_to_raw_data': struct.unpack('<I', section_data[20:24])[0],
                'characteristics': struct.unpack('<I', section_data[36:40])[0]
            }
            
            # Section data çıkar
            if section['pointer_to_raw_data'] and section['size_of_raw_data']:
                start = section['pointer_to_raw_data']
                end = start + section['size_of_raw_data']
                if end <= len(self.file_data):
                    section['data'] = self.file_data[start:end]
            
            self.sections.append(section)
            
        return True
    
    def create_project_structure(self):
        """Proje dizin yapısını oluştur"""
        file_base = os.path.splitext(os.path.basename(self.file_path))[0]
        
        # Ana proje dizini
        project_root = os.path.join(self.output_dir, f"{file_base}_reconstructed")
        os.makedirs(project_root, exist_ok=True)
        
        # Alt dizinler
        subdirs = {
            'source': os.path.join(project_root, 'src'),
            'include': os.path.join(project_root, 'include'),
            'resources': os.path.join(project_root, 'resources'),
            'data': os.path.join(project_root, 'data'),
            'libs': os.path.join(project_root, 'libs'),
            'docs': os.path.join(project_root, 'docs'),
            'build': os.path.join(project_root, 'build'),
            'sections': os.path.join(project_root, 'sections')
        }
        
        for subdir_path in subdirs.values():
            os.makedirs(subdir_path, exist_ok=True)
        
        self.project_structure = {
            'root': project_root,
            **subdirs
        }
        
        return project_root
    
    def extract_sections_as_files(self):
        """Her section'ı ayrı dosya olarak çıkar"""
        extracted_files = []
        
        for section in self.sections:
            if not section.get('data'):
                continue
                
            # Section dosya adı
            section_name = section['name'].replace('.', '_')
            if not section_name:
                section_name = f"section_{section['virtual_address']:08x}"
            
            # Raw binary dosyası
            bin_file = os.path.join(self.project_structure['sections'], f"{section_name}.bin")
            with open(bin_file, 'wb') as f:
                f.write(section['data'])
            extracted_files.append(bin_file)
            
            # Section bilgileri
            info_file = os.path.join(self.project_structure['sections'], f"{section_name}_info.txt")
            with open(info_file, 'w') as f:
                f.write(f"Section Information: {section['name']}\\n")
                f.write("=" * 40 + "\\n\\n")
                f.write(f"Virtual Address: 0x{section['virtual_address']:08x}\\n")
                f.write(f"Virtual Size: {section['virtual_size']:,} bytes\\n")
                f.write(f"Raw Address: 0x{section['pointer_to_raw_data']:08x}\\n")
                f.write(f"Raw Size: {section['size_of_raw_data']:,} bytes\\n")
                f.write(f"Characteristics: 0x{section['characteristics']:08x}\\n")
                
                # Characteristics decode
                chars = []
                if section['characteristics'] & 0x20: chars.append("CODE")
                if section['characteristics'] & 0x40: chars.append("INITIALIZED_DATA")
                if section['characteristics'] & 0x80: chars.append("UNINITIALIZED_DATA")
                if section['characteristics'] & 0x20000000: chars.append("EXECUTABLE")
                if section['characteristics'] & 0x40000000: chars.append("READABLE")
                if section['characteristics'] & 0x80000000: chars.append("WRITABLE")
                
                if chars:
                    f.write(f"Flags: {', '.join(chars)}\\n")
                
                # Entropy ve analiz
                entropy = self.calculate_entropy(section['data'])
                f.write(f"\\nEntropy: {entropy:.2f}\\n")
                
                if entropy > 7.0:
                    f.write("⚠️  High entropy - possibly packed/encrypted\\n")
                elif section['characteristics'] & 0x20:
                    f.write("📋 Executable code section\\n")
                elif section['characteristics'] & 0x40:
                    f.write("📊 Initialized data section\\n")
            
            extracted_files.append(info_file)
            
            # Executable section ise disassembly yap
            if section['characteristics'] & 0x20000000:  # EXECUTABLE
                asm_file = os.path.join(self.project_structure['source'], f"{section_name}.asm")
                self.create_assembly_file(section, asm_file)
                extracted_files.append(asm_file)
        
        return extracted_files
    
    def create_assembly_file(self, section, output_file):
        """Section için assembly dosyası oluştur"""
        with open(output_file, 'w') as f:
            f.write(f"; Assembly code from {section['name']} section\\n")
            f.write(f"; Virtual Address: 0x{section['virtual_address']:08x}\\n")
            f.write(f"; Size: {len(section['data'])} bytes\\n\\n")
            
            f.write(f"section {section['name']}\\n\\n")
            
            # Basit disassembly (daha detaylı için disassembler.py kullan)
            data = section['data']
            offset = 0
            while offset < len(data) and offset < 1000:  # İlk 1000 byte
                if offset + 1 < len(data):
                    byte1 = data[offset]
                    byte2 = data[offset + 1] if offset + 1 < len(data) else 0
                    
                    f.write(f"    db 0x{byte1:02x}")
                    if byte1 >= 32 and byte1 <= 126:
                        f.write(f"  ; '{chr(byte1)}'")
                    f.write("\\n")
                    
                offset += 1
    
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
    
    def create_makefile(self):
        """Makefile oluştur"""
        file_base = os.path.splitext(os.path.basename(self.file_path))[0]
        makefile_path = os.path.join(self.project_structure['root'], 'Makefile')
        
        with open(makefile_path, 'w') as f:
            f.write(f"# Reconstructed Makefile for {file_base}\\n")
            f.write("# Generated by File Reconstructor\\n\\n")
            
            f.write("CC = gcc\\n")
            f.write("CXX = g++\\n")
            f.write("CFLAGS = -Wall -O2\\n")
            f.write("CXXFLAGS = -Wall -O2\\n")
            f.write("LDFLAGS =\\n\\n")
            
            f.write(f"TARGET = {file_base}\\n")
            f.write("SRCDIR = src\\n")
            f.write("BUILDDIR = build\\n")
            f.write("SOURCES = $(wildcard $(SRCDIR)/*.c $(SRCDIR)/*.cpp)\\n")
            f.write("OBJECTS = $(SOURCES:$(SRCDIR)/%.c=$(BUILDDIR)/%.o)\\n\\n")
            
            f.write("all: $(TARGET)\\n\\n")
            
            f.write("$(TARGET): $(OBJECTS)\\n")
            f.write("\\t$(CC) $(OBJECTS) -o $@ $(LDFLAGS)\\n\\n")
            
            f.write("$(BUILDDIR)/%.o: $(SRCDIR)/%.c\\n")
            f.write("\\t@mkdir -p $(BUILDDIR)\\n")
            f.write("\\t$(CC) $(CFLAGS) -c $< -o $@\\n\\n")
            
            f.write("clean:\\n")
            f.write("\\trm -rf $(BUILDDIR) $(TARGET)\\n\\n")
            
            f.write("rebuild: clean all\\n\\n")
            
            f.write(".PHONY: all clean rebuild\\n")
        
        return makefile_path
    
    def create_project_readme(self):
        """README dosyası oluştur"""
        file_base = os.path.splitext(os.path.basename(self.file_path))[0]
        readme_path = os.path.join(self.project_structure['root'], 'README.md')
        
        with open(readme_path, 'w') as f:
            f.write(f"# Reconstructed Project: {file_base}\\n\\n")
            f.write("Bu proje reverse engineering araçları ile otomatik olarak oluşturulmuştur.\\n\\n")
            
            f.write("## Dosya Bilgileri\\n\\n")
            f.write(f"- **Kaynak Dosya**: {os.path.basename(self.file_path)}\\n")
            f.write(f"- **Dosya Boyutu**: {len(self.file_data):,} bytes\\n")
            f.write(f"- **MD5**: {hashlib.md5(self.file_data).hexdigest()}\\n")
            f.write(f"- **SHA256**: {hashlib.sha256(self.file_data).hexdigest()}\\n\\n")
            
            f.write("## Proje Yapısı\\n\\n")
            f.write("```\\n")
            f.write(f"{file_base}_reconstructed/\\n")
            f.write("├── src/           # Source code files\\n")
            f.write("├── include/       # Header files\\n")
            f.write("├── resources/     # Resource files\\n")
            f.write("├── data/          # Data files\\n")
            f.write("├── libs/          # Library files\\n")
            f.write("├── sections/      # PE section dumps\\n")
            f.write("├── build/         # Build directory\\n")
            f.write("├── docs/          # Documentation\\n")
            f.write("├── Makefile       # Build configuration\\n")
            f.write("└── README.md      # This file\\n")
            f.write("```\\n\\n")
            
            f.write("## PE Sections\\n\\n")
            f.write("| Section | Virtual Addr | Size | Type |\\n")
            f.write("|---------|-------------|------|------|\\n")
            
            for section in self.sections:
                section_type = "Unknown"
                if section['characteristics'] & 0x20000000:
                    section_type = "Executable"
                elif section['characteristics'] & 0x40:
                    section_type = "Data"
                elif section['characteristics'] & 0x80:
                    section_type = "BSS"
                    
                f.write(f"| {section['name']} | 0x{section['virtual_address']:08x} | "
                       f"{section['size_of_raw_data']:,} | {section_type} |\\n")
            
            f.write("\\n## Build Instructions\\n\\n")
            f.write("```bash\\n")
            f.write("# Compile the project\\n")
            f.write("make\\n\\n")
            f.write("# Clean build files\\n")
            f.write("make clean\\n\\n")
            f.write("# Rebuild everything\\n")
            f.write("make rebuild\\n")
            f.write("```\\n\\n")
            
            f.write("## Güvenlik Uyarısı\\n\\n")
            f.write("⚠️ Bu dosyalar reverse engineering ile elde edilmiştir.\\n")
            f.write("- Orijinal source kod değildir\\n")
            f.write("- Sadece analiz amacıyla kullanılmalıdır\\n")
            f.write("- Telif hakkı ve lisans kurallarına dikkat edilmelidir\\n")
        
        return readme_path
    
    def create_git_structure(self):
        """Git repository yapısı oluştur"""
        git_dir = os.path.join(self.project_structure['root'], '.git')
        
        # .gitignore
        gitignore_path = os.path.join(self.project_structure['root'], '.gitignore')
        with open(gitignore_path, 'w') as f:
            f.write("# Build artifacts\\n")
            f.write("build/\\n")
            f.write("*.o\\n")
            f.write("*.exe\\n")
            f.write("*.dll\\n")
            f.write("*.so\\n\\n")
            
            f.write("# IDE files\\n")
            f.write(".vscode/\\n")
            f.write(".idea/\\n")
            f.write("*.swp\\n")
            f.write("*.swo\\n\\n")
            
            f.write("# OS files\\n")
            f.write(".DS_Store\\n")
            f.write("Thumbs.db\\n")
        
        return gitignore_path
    
    def reconstruct(self):
        """Ana reconstruction fonksiyonu"""
        if not self.load_file():
            return False
            
        if not self.parse_pe_structure():
            print("❌ PE yapısı parse edilemedi")
            return False
            
        print(f"🔧 FILE RECONSTRUCTION: {os.path.basename(self.file_path)}")
        print("=" * 80)
        
        # Proje yapısını oluştur
        print("📁 Proje dizin yapısı oluşturuluyor...")
        project_root = self.create_project_structure()
        
        # Section'ları extract et
        print("📋 PE section'ları extract ediliyor...")
        extracted_files = self.extract_sections_as_files()
        print(f"   {len(extracted_files)} dosya oluşturuldu")
        
        # Build dosyaları oluştur
        print("🔨 Build yapısı oluşturuluyor...")
        makefile = self.create_makefile()
        readme = self.create_project_readme()
        gitignore = self.create_git_structure()
        
        # Özet bilgi
        print(f"\\n📊 RECONSTRUCTION SUMMARY")
        print(f"   Project Root: {project_root}")
        print(f"   Sections Extracted: {len(self.sections)}")
        print(f"   Total Files Created: {len(extracted_files) + 3}")
        
        print(f"\\n📂 Created Files:")
        print(f"   📋 {makefile}")
        print(f"   📖 {readme}")
        print(f"   🚫 {gitignore}")
        
        for section in self.sections:
            section_name = section['name'] or f"section_{section['virtual_address']:08x}"
            print(f"   🗂️  sections/{section_name}.bin ({section['size_of_raw_data']:,} bytes)")
        
        print(f"\\n✅ File reconstruction tamamlandı!")
        print(f"📂 Proje dizini: {project_root}")
        
        return True

def main():
    if len(sys.argv) < 2:
        print("Kullanım: python file_reconstructor.py <exe_dosyasi> [output_dir]")
        print("\\nÖzellikler:")
        print("  - PE section'larını ayrı dosyalar olarak çıkarır")
        print("  - Proje dizin yapısı oluşturur")
        print("  - Makefile ve README dosyaları oluşturur")
        print("  - Git repository yapısı hazırlar")
        sys.exit(1)
    
    file_path = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else "extracted/reconstructed"
    
    if not os.path.exists(file_path):
        print(f"Dosya bulunamadı: {file_path}")
        sys.exit(1)
    
    reconstructor = FileReconstructor(file_path, output_dir)
    reconstructor.reconstruct()

if __name__ == "__main__":
    main()