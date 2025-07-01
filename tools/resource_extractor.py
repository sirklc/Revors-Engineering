#!/usr/bin/env python3
"""
Resource Extractor
PE dosyalarından icon, string, dialog, manifest ve diğer kaynakları çıkarma
"""

import sys
import os
import struct
from collections import defaultdict

class ResourceExtractor:
    def __init__(self, file_path, output_dir="extracted/resources"):
        self.file_path = file_path
        self.output_dir = output_dir
        self.file_data = None
        self.pe_offset = None
        self.resource_directory = None
        self.resources = []
        
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
        """PE yapısını parse et"""
        if len(self.file_data) < 64:
            return False
            
        if self.file_data[:2] != b'MZ':
            return False
            
        self.pe_offset = struct.unpack('<I', self.file_data[60:64])[0]
        
        if self.file_data[self.pe_offset:self.pe_offset+4] != b'PE\x00\x00':
            return False
            
        return True
    
    def get_resource_directory_rva(self):
        """Resource Directory RVA'sını al"""
        opt_header_offset = self.pe_offset + 24
        
        # PE32 veya PE32+ kontrol et
        magic = struct.unpack('<H', self.file_data[opt_header_offset:opt_header_offset + 2])[0]
        
        if magic == 0x10b:  # PE32
            resource_dir_offset = opt_header_offset + 112
        elif magic == 0x20b:  # PE32+
            resource_dir_offset = opt_header_offset + 128
        else:
            return None, None
            
        if resource_dir_offset + 8 > len(self.file_data):
            return None, None
            
        resource_rva = struct.unpack('<I', self.file_data[resource_dir_offset:resource_dir_offset + 4])[0]
        resource_size = struct.unpack('<I', self.file_data[resource_dir_offset + 4:resource_dir_offset + 8])[0]
        
        return resource_rva, resource_size
    
    def rva_to_offset(self, rva):
        """RVA'yı file offset'e çevir"""
        # Section table'ı parse et
        section_count = struct.unpack('<H', self.file_data[self.pe_offset + 6:self.pe_offset + 8])[0]
        section_table_offset = self.pe_offset + 24 + 224
        
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
    
    def parse_resource_directory(self, dir_rva, level=0, path=""):
        """Resource directory'yi recursive parse et"""
        dir_offset = self.rva_to_offset(dir_rva)
        if not dir_offset or dir_offset + 16 > len(self.file_data):
            return []
        
        resources = []
        
        # Resource directory header
        characteristics = struct.unpack('<I', self.file_data[dir_offset:dir_offset + 4])[0]
        timestamp = struct.unpack('<I', self.file_data[dir_offset + 4:dir_offset + 8])[0]
        major_version = struct.unpack('<H', self.file_data[dir_offset + 8:dir_offset + 10])[0]
        minor_version = struct.unpack('<H', self.file_data[dir_offset + 10:dir_offset + 12])[0]
        num_name_entries = struct.unpack('<H', self.file_data[dir_offset + 12:dir_offset + 14])[0]
        num_id_entries = struct.unpack('<H', self.file_data[dir_offset + 14:dir_offset + 16])[0]
        
        entry_offset = dir_offset + 16
        
        # Name entries
        for i in range(num_name_entries + num_id_entries):
            if entry_offset + 8 > len(self.file_data):
                break
                
            name_or_id = struct.unpack('<I', self.file_data[entry_offset:entry_offset + 4])[0]
            offset_to_data_or_subdir = struct.unpack('<I', self.file_data[entry_offset + 4:entry_offset + 8])[0]
            
            # Name veya ID
            if name_or_id & 0x80000000:  # Name
                name_rva = name_or_id & 0x7FFFFFFF
                name_offset = self.rva_to_offset(name_rva)
                if name_offset:
                    name_length = struct.unpack('<H', self.file_data[name_offset:name_offset + 2])[0]
                    name_data = self.file_data[name_offset + 2:name_offset + 2 + (name_length * 2)]
                    resource_name = name_data.decode('utf-16le', errors='ignore')
                else:
                    resource_name = f"name_{name_or_id:08x}"
            else:  # ID
                resource_name = self.get_resource_type_name(name_or_id) if level == 0 else str(name_or_id)
            
            current_path = f"{path}/{resource_name}" if path else resource_name
            
            # Data veya subdirectory
            if offset_to_data_or_subdir & 0x80000000:  # Subdirectory
                subdir_rva = dir_rva + (offset_to_data_or_subdir & 0x7FFFFFFF)
                sub_resources = self.parse_resource_directory(subdir_rva, level + 1, current_path)
                resources.extend(sub_resources)
            else:  # Data entry
                data_entry_offset = self.rva_to_offset(dir_rva + offset_to_data_or_subdir)
                if data_entry_offset and data_entry_offset + 16 <= len(self.file_data):
                    data_rva = struct.unpack('<I', self.file_data[data_entry_offset:data_entry_offset + 4])[0]
                    data_size = struct.unpack('<I', self.file_data[data_entry_offset + 4:data_entry_offset + 8])[0]
                    codepage = struct.unpack('<I', self.file_data[data_entry_offset + 8:data_entry_offset + 12])[0]
                    
                    data_offset = self.rva_to_offset(data_rva)
                    if data_offset and data_offset + data_size <= len(self.file_data):
                        resource_data = self.file_data[data_offset:data_offset + data_size]
                        
                        resources.append({
                            'path': current_path,
                            'name': resource_name,
                            'type': path.split('/')[0] if '/' in current_path else current_path,
                            'size': data_size,
                            'rva': data_rva,
                            'offset': data_offset,
                            'codepage': codepage,
                            'data': resource_data
                        })
            
            entry_offset += 8
        
        return resources
    
    def get_resource_type_name(self, resource_id):
        """Resource type ID'sini isime çevir"""
        types = {
            1: "CURSOR",
            2: "BITMAP", 
            3: "ICON",
            4: "MENU",
            5: "DIALOG",
            6: "STRING",
            7: "FONTDIR",
            8: "FONT",
            9: "ACCELERATOR",
            10: "RCDATA",
            11: "MESSAGETABLE",
            12: "GROUP_CURSOR",
            14: "GROUP_ICON",
            16: "VERSION",
            17: "DLGINCLUDE",
            19: "PLUGPLAY",
            20: "VXD",
            21: "ANICURSOR",
            22: "ANIICON",
            23: "HTML",
            24: "MANIFEST"
        }
        return types.get(resource_id, f"TYPE_{resource_id}")
    
    def extract_icon(self, resource_data, filename):
        """Icon dosyasını çıkar"""
        if len(resource_data) < 6:
            return False
            
        # Icon header
        with open(filename, 'wb') as f:
            # ICO file header
            f.write(struct.pack('<HHH', 0, 1, 1))  # Reserved, Type, Count
            
            # Icon directory entry
            f.write(struct.pack('<BBBBHHII', 
                               0, 0, 0, 0,  # Width, Height, Colors, Reserved
                               1, 0,        # Planes, BitCount
                               len(resource_data),  # Size
                               22))         # Offset
            
            # Icon data
            f.write(resource_data)
        
        return True
    
    def extract_bitmap(self, resource_data, filename):
        """Bitmap dosyasını çıkar"""
        if len(resource_data) < 40:  # BITMAPINFOHEADER minimum size
            return False
            
        # BMP file header ekle
        with open(filename, 'wb') as f:
            # BMP file header
            f.write(b'BM')  # Signature
            f.write(struct.pack('<I', 14 + len(resource_data)))  # File size
            f.write(struct.pack('<HH', 0, 0))  # Reserved
            f.write(struct.pack('<I', 14 + 40))  # Offset to pixel data
            
            # Bitmap data
            f.write(resource_data)
        
        return True
    
    def extract_string_table(self, resource_data, filename):
        """String table'ı extract et"""
        with open(filename, 'w', encoding='utf-8') as f:
            f.write("String Table Resources\\n")
            f.write("=" * 30 + "\\n\\n")
            
            offset = 0
            string_id = 0
            
            while offset < len(resource_data) - 2:
                # String length (2 bytes)
                str_len = struct.unpack('<H', resource_data[offset:offset + 2])[0]
                offset += 2
                
                if str_len > 0 and offset + (str_len * 2) <= len(resource_data):
                    # UTF-16 string
                    string_data = resource_data[offset:offset + (str_len * 2)]
                    try:
                        string_text = string_data.decode('utf-16le')
                        f.write(f"String {string_id}: {string_text}\\n")
                    except:
                        f.write(f"String {string_id}: [DECODE_ERROR]\\n")
                    
                    offset += str_len * 2
                
                string_id += 1
                
                # Too many strings, break
                if string_id > 1000:
                    break
        
        return True
    
    def extract_version_info(self, resource_data, filename):
        """Version info'yu extract et"""
        with open(filename, 'w', encoding='utf-8') as f:
            f.write("Version Information\\n")
            f.write("=" * 30 + "\\n\\n")
            
            if len(resource_data) < 6:
                f.write("Invalid version resource\\n")
                return False
            
            # VS_VERSIONINFO header
            length = struct.unpack('<H', resource_data[0:2])[0]
            value_length = struct.unpack('<H', resource_data[2:4])[0]
            type_field = struct.unpack('<H', resource_data[4:6])[0]
            
            f.write(f"Length: {length}\\n")
            f.write(f"Value Length: {value_length}\\n")
            f.write(f"Type: {type_field}\\n\\n")
            
            # Version info string'lerini ara
            try:
                version_str = resource_data.decode('utf-16le', errors='ignore')
                f.write("Raw Version Data:\\n")
                f.write("-" * 20 + "\\n")
                f.write(version_str)
            except:
                f.write("Could not decode version information\\n")
        
        return True
    
    def extract_manifest(self, resource_data, filename):
        """Manifest dosyasını extract et"""
        try:
            # XML manifest
            manifest_text = resource_data.decode('utf-8', errors='ignore')
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(manifest_text)
            return True
        except:
            # Binary manifest
            with open(filename, 'wb') as f:
                f.write(resource_data)
            return True
    
    def save_resource(self, resource, file_base):
        """Kaynağı uygun formatta kaydet"""
        resource_type = resource['type'].upper()
        safe_name = resource['name'].replace('/', '_').replace('\\', '_')
        
        if resource_type == "ICON":
            filename = os.path.join(self.output_dir, f"{file_base}_{safe_name}.ico")
            success = self.extract_icon(resource['data'], filename)
        elif resource_type == "BITMAP":
            filename = os.path.join(self.output_dir, f"{file_base}_{safe_name}.bmp")
            success = self.extract_bitmap(resource['data'], filename)
        elif resource_type == "STRING":
            filename = os.path.join(self.output_dir, f"{file_base}_{safe_name}_strings.txt")
            success = self.extract_string_table(resource['data'], filename)
        elif resource_type == "VERSION":
            filename = os.path.join(self.output_dir, f"{file_base}_{safe_name}_version.txt")
            success = self.extract_version_info(resource['data'], filename)
        elif resource_type == "MANIFEST":
            filename = os.path.join(self.output_dir, f"{file_base}_{safe_name}_manifest.xml")
            success = self.extract_manifest(resource['data'], filename)
        else:
            # Raw binary export
            filename = os.path.join(self.output_dir, f"{file_base}_{safe_name}_{resource_type.lower()}.bin")
            with open(filename, 'wb') as f:
                f.write(resource['data'])
            success = True
        
        if success:
            # Resource info dosyası
            info_filename = os.path.join(self.output_dir, f"{file_base}_{safe_name}_info.txt")
            with open(info_filename, 'w') as f:
                f.write(f"Resource Information\\n")
                f.write("=" * 30 + "\\n\\n")
                f.write(f"Path: {resource['path']}\\n")
                f.write(f"Name: {resource['name']}\\n")
                f.write(f"Type: {resource['type']}\\n")
                f.write(f"Size: {resource['size']:,} bytes\\n")
                f.write(f"RVA: 0x{resource['rva']:08x}\\n")
                f.write(f"File Offset: 0x{resource['offset']:08x}\\n")
                f.write(f"Codepage: {resource['codepage']}\\n")
            
            return [filename, info_filename]
        
        return []
    
    def analyze(self):
        """Ana analiz fonksiyonu"""
        if not self.load_file():
            return False
            
        print(f"🎨 RESOURCE EXTRACTION: {os.path.basename(self.file_path)}")
        print("=" * 80)
        
        if not self.parse_pe_structure():
            print("❌ PE yapısı parse edilemedi")
            self.save_no_resources_info()
            return True
            
        # Resource directory RVA al
        resource_rva, resource_size = self.get_resource_directory_rva()
        
        if not resource_rva or not resource_size:
            print("❌ Resource directory bulunamadı")
            print("   Bu dosya resource içermiyor")
            self.save_no_resources_info()
            return True
        
        print(f"📂 Resource Directory: RVA 0x{resource_rva:08x}, Size: {resource_size:,} bytes")
        
        # Resource'ları parse et
        try:
            self.resources = self.parse_resource_directory(resource_rva)
        except Exception as e:
            print(f"❌ Resource parsing hatası: {e}")
            self.save_no_resources_info()
            return True
        
        if not self.resources:
            print("❌ Hiç resource bulunamadı")
            self.save_no_resources_info()
            return True
        
        print(f"✅ {len(self.resources)} adet resource bulundu")
        
        # Resource tipleri sayısı
        resource_types = defaultdict(int)
        for resource in self.resources:
            resource_types[resource['type']] += 1
        
        print(f"\\n📊 Resource Tipleri:")
        for res_type, count in resource_types.items():
            print(f"   {res_type}: {count} adet")
        
        # Resource'ları kaydet
        file_base = os.path.splitext(os.path.basename(self.file_path))[0]
        saved_files = []
        
        print(f"\\n💾 Resource'lar kaydediliyor...")
        for i, resource in enumerate(self.resources):
            print(f"   [{i+1}/{len(self.resources)}] {resource['type']}/{resource['name']}")
            files = self.save_resource(resource, file_base)
            saved_files.extend(files)
        
        # Özet rapor
        summary_file = os.path.join(self.output_dir, f"{file_base}_resource_summary.txt")
        with open(summary_file, 'w') as f:
            f.write(f"Resource Extraction Summary\\n")
            f.write("=" * 50 + "\\n\\n")
            f.write(f"Source File: {self.file_path}\\n")
            f.write(f"Total Resources: {len(self.resources)}\\n\\n")
            
            f.write("Resource Types:\\n")
            f.write("-" * 20 + "\\n")
            for res_type, count in resource_types.items():
                f.write(f"{res_type}: {count}\\n")
            
            f.write("\\nDetailed Resources:\\n")
            f.write("-" * 20 + "\\n")
            for resource in self.resources:
                f.write(f"Path: {resource['path']}\\n")
                f.write(f"Type: {resource['type']}\\n")
                f.write(f"Size: {resource['size']:,} bytes\\n")
                f.write(f"RVA: 0x{resource['rva']:08x}\\n")
                f.write("\\n")
        
        saved_files.append(summary_file)
        
        print(f"\\n📋 Oluşturulan dosyalar:")
        for file_path in saved_files[:20]:  # İlk 20 dosyayı göster
            print(f"   📄 {os.path.basename(file_path)}")
        
        if len(saved_files) > 20:
            print(f"   ... ve {len(saved_files) - 20} dosya daha")
        
        print(f"\\n✅ Resource extraction tamamlandı!")
        print(f"📂 Çıktı dizini: {self.output_dir}")
        return True
    
    def save_no_resources_info(self):
        """Resource bulunamadığında bilgi dosyası oluştur"""
        file_base = os.path.splitext(os.path.basename(self.file_path))[0]
        info_file = os.path.join(self.output_dir, f"{file_base}_resource_info.txt")
        
        with open(info_file, 'w') as f:
            f.write(f"Resource Analysis: {os.path.basename(self.file_path)}\\n")
            f.write("=" * 50 + "\\n\\n")
            f.write("RESULT: No resources found\\n\\n")
            f.write("This file either:\\n")
            f.write("- Contains no embedded resources\\n")
            f.write("- Has corrupted resource directory\\n")
            f.write("- Is not a valid PE file\\n\\n")
            f.write(f"File Size: {len(self.file_data):,} bytes\\n")
            
            # File header bilgisi
            if len(self.file_data) >= 32:
                f.write("\\nFile Header (first 32 bytes):\\n")
                hex_data = ' '.join(f'{b:02x}' for b in self.file_data[:32])
                f.write(f"  {hex_data}\\n")
        
        print(f"📄 Resource info saved: {info_file}")

def main():
    if len(sys.argv) < 2:
        print("Kullanım: python resource_extractor.py <exe_dosyasi> [output_dir]")
        print("\\nÇıkarılabilir resource tipleri:")
        print("  - Icons (.ico)")
        print("  - Bitmaps (.bmp)")
        print("  - Strings (.txt)")
        print("  - Version Info (.txt)")
        print("  - Manifests (.xml)")
        print("  - Other resources (.bin)")
        sys.exit(1)
    
    file_path = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else "extracted/resources"
    
    if not os.path.exists(file_path):
        print(f"Dosya bulunamadı: {file_path}")
        sys.exit(1)
    
    extractor = ResourceExtractor(file_path, output_dir)
    extractor.analyze()

if __name__ == "__main__":
    main()