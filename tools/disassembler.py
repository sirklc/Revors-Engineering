#!/usr/bin/env python3
"""
Advanced Disassembler
PE dosyalarından assembly kod çıkarma ve source kod rekonstruksiyonu
"""

import sys
import os
import struct
from collections import defaultdict
import re

try:
    import capstone
    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False
    print("⚠️  Capstone engine bulunamadı. Basit disassembly kullanılacak.")

class AdvancedDisassembler:
    def __init__(self, file_path, output_dir="extracted/source_code"):
        self.file_path = file_path
        self.output_dir = output_dir
        self.file_data = None
        self.pe_offset = None
        self.entry_point = None
        self.sections = []
        self.functions = []
        self.strings = []
        self.code_sections = []
        
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
        try:
            if len(self.file_data) < 64:
                print("❌ Dosya PE formatında değil (çok küçük)")
                return False
                
            # DOS header
            if self.file_data[:2] != b'MZ':
                print("❌ DOS signature bulunamadı")
                return False
                
            self.pe_offset = struct.unpack('<I', self.file_data[60:64])[0]
            
            if self.pe_offset >= len(self.file_data) - 4:
                print("❌ PE offset geçersiz")
                return False
            
            # PE signature
            if self.file_data[self.pe_offset:self.pe_offset+4] != b'PE\x00\x00':
                print("❌ PE signature bulunamadı")
                return False
            
            print("✅ PE dosyası doğrulandı")
            
            # Optional header'dan entry point'i al
            opt_header_offset = self.pe_offset + 24
            if opt_header_offset + 20 <= len(self.file_data):
                self.entry_point = struct.unpack('<I', self.file_data[opt_header_offset + 16:opt_header_offset + 20])[0]
                print(f"📍 Entry Point: 0x{self.entry_point:08x}")
            
            # Sections parse et
            section_count = struct.unpack('<H', self.file_data[self.pe_offset + 6:self.pe_offset + 8])[0]
            print(f"📋 Section sayısı: {section_count}")
            
            # Optional header size al
            opt_header_size = struct.unpack('<H', self.file_data[self.pe_offset + 20:self.pe_offset + 22])[0]
            section_table_offset = self.pe_offset + 24 + opt_header_size
            
            for i in range(section_count):
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
                
                # Section data çıkar
                if (section['pointer_to_raw_data'] > 0 and 
                    section['size_of_raw_data'] > 0 and
                    section['pointer_to_raw_data'] + section['size_of_raw_data'] <= len(self.file_data)):
                    
                    start = section['pointer_to_raw_data']
                    end = start + section['size_of_raw_data']
                    section['data'] = self.file_data[start:end]
                else:
                    section['data'] = b''
                
                # Executable section mı kontrol et
                if section['characteristics'] & 0x20000000:  # IMAGE_SCN_MEM_EXECUTE
                    section['is_executable'] = True
                    self.code_sections.append(section)
                    print(f"🔧 Executable section bulundu: {section['name']}")
                else:
                    section['is_executable'] = False
                    
                self.sections.append(section)
                
            print(f"✅ {len(self.code_sections)} executable section bulundu")
            return len(self.sections) > 0
            
        except Exception as e:
            print(f"❌ PE parsing hatası: {e}")
            return False
    
    def disassemble_with_capstone(self, data, base_address=0):
        """Capstone ile disassembly"""
        if not CAPSTONE_AVAILABLE:
            return self.basic_disassembly(data, base_address)
            
        try:
            # x86 varsayımı
            md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
            md.detail = True
            
            instructions = []
            for instruction in md.disasm(data, base_address):
                instructions.append({
                    'address': instruction.address,
                    'mnemonic': instruction.mnemonic,
                    'op_str': instruction.op_str,
                    'bytes': instruction.bytes.hex(),
                    'size': instruction.size
                })
                
            return instructions
            
        except Exception as e:
            print(f"Capstone disassembly hatası: {e}")
            return self.basic_disassembly(data, base_address)
    
    def basic_disassembly(self, data, base_address=0):
        """Basit disassembly (Capstone yoksa)"""
        instructions = []
        offset = 0
        
        while offset < len(data) - 1:
            # Basit x86 instruction patterns
            byte = data[offset]
            
            # Common instructions
            if byte == 0x90:  # NOP
                instructions.append({
                    'address': base_address + offset,
                    'mnemonic': 'nop',
                    'op_str': '',
                    'bytes': f'{byte:02x}',
                    'size': 1
                })
                offset += 1
            elif byte == 0xC3:  # RET
                instructions.append({
                    'address': base_address + offset,
                    'mnemonic': 'ret',
                    'op_str': '',
                    'bytes': f'{byte:02x}',
                    'size': 1
                })
                offset += 1
            elif byte == 0x55:  # PUSH EBP
                instructions.append({
                    'address': base_address + offset,
                    'mnemonic': 'push',
                    'op_str': 'ebp',
                    'bytes': f'{byte:02x}',
                    'size': 1
                })
                offset += 1
            elif byte == 0x5D:  # POP EBP
                instructions.append({
                    'address': base_address + offset,
                    'mnemonic': 'pop',
                    'op_str': 'ebp',
                    'bytes': f'{byte:02x}',
                    'size': 1
                })
                offset += 1
            else:
                # Unknown instruction
                instructions.append({
                    'address': base_address + offset,
                    'mnemonic': 'db',
                    'op_str': f'0x{byte:02x}',
                    'bytes': f'{byte:02x}',
                    'size': 1
                })
                offset += 1
                
        return instructions
    
    def identify_functions(self, instructions):
        """Fonksiyonları tespit et"""
        functions = []
        current_function = None
        
        for i, inst in enumerate(instructions):
            # Function prologue detection
            if (inst['mnemonic'] == 'push' and inst['op_str'] == 'ebp' and 
                i + 1 < len(instructions) and 
                instructions[i + 1]['mnemonic'] == 'mov' and 
                'ebp' in instructions[i + 1]['op_str']):
                
                if current_function:
                    functions.append(current_function)
                    
                current_function = {
                    'start_address': inst['address'],
                    'instructions': [inst],
                    'name': f'sub_{inst["address"]:08x}'
                }
            elif current_function:
                current_function['instructions'].append(inst)
                
                # Function epilogue detection
                if inst['mnemonic'] == 'ret':
                    current_function['end_address'] = inst['address']
                    functions.append(current_function)
                    current_function = None
        
        if current_function:
            functions.append(current_function)
            
        return functions
    
    def generate_c_pseudocode(self, function):
        """C-like pseudocode oluştur"""
        pseudocode = []
        pseudocode.append(f"// Function: {function['name']}")
        pseudocode.append(f"// Address: 0x{function['start_address']:08x}")
        pseudocode.append(f"void {function['name']}() {{")
        
        for inst in function['instructions']:
            # Basic instruction to C conversion
            if inst['mnemonic'] == 'push':
                pseudocode.append(f"    // push {inst['op_str']}")
            elif inst['mnemonic'] == 'pop':
                pseudocode.append(f"    // pop {inst['op_str']}")
            elif inst['mnemonic'] == 'mov':
                pseudocode.append(f"    // {inst['op_str'].replace(',', ' = ')}")
            elif inst['mnemonic'] == 'call':
                if 'sub_' in inst['op_str']:
                    pseudocode.append(f"    {inst['op_str']}();")
                else:
                    pseudocode.append(f"    // call {inst['op_str']}")
            elif inst['mnemonic'] == 'ret':
                pseudocode.append(f"    return;")
            else:
                pseudocode.append(f"    // {inst['mnemonic']} {inst['op_str']}")
                
        pseudocode.append("}")
        pseudocode.append("")
        
        return '\n'.join(pseudocode)
    
    def extract_constants_and_strings(self, instructions):
        """Constants ve stringleri çıkar"""
        constants = set()
        addresses = set()
        
        for inst in instructions:
            # Hex constants
            hex_matches = re.findall(r'0x[0-9a-fA-F]+', inst['op_str'])
            constants.update(hex_matches)
            
            # Memory addresses
            addr_matches = re.findall(r'\[0x[0-9a-fA-F]+\]', inst['op_str'])
            for addr in addr_matches:
                addresses.add(addr.strip('[]'))
                
        return list(constants), list(addresses)
    
    def disassemble_and_extract(self):
        """Ana disassembly ve extraction fonksiyonu"""
        if not self.load_file():
            return False
            
        if not self.parse_pe_structure():
            print("❌ PE yapısı parse edilemedi")
            return False
            
        print(f"🔍 DISASSEMBLY: {os.path.basename(self.file_path)}")
        print("=" * 80)
        
        file_base = os.path.splitext(os.path.basename(self.file_path))[0]
        files_created = []
        
        if not self.code_sections:
            print("⚠️  Executable section bulunamadı, tüm section'ları analiz ediliyor...")
            # Executable section yoksa tüm section'ları kontrol et
            for section in self.sections:
                if section.get('data') and len(section['data']) > 0:
                    self.code_sections.append(section)
        
        # Her section için disassembly (executable olmayanlar da dahil)
        for i, section in enumerate(self.code_sections):
            section_name = section['name'] if section['name'] else f"section_{i}"
            print(f"\n📋 Section: {section_name}")
            
            if not section.get('data'):
                print(f"   ⚠️  Section data bulunamadı")
                continue
                
            section_data = section['data']
            print(f"   Data Size: {len(section_data)} bytes")
            
            # Disassemble
            instructions = self.disassemble_with_capstone(
                section_data, 
                section['virtual_address']
            )
            
            print(f"   Instructions: {len(instructions)}")
            
            if len(instructions) > 0:
                # Assembly dosyası yaz
                asm_file = os.path.join(self.output_dir, f"{file_base}_{section_name}.asm")
                with open(asm_file, 'w') as f:
                    f.write(f"; Disassembly of {section_name} section\n")
                    f.write(f"; Virtual Address: 0x{section['virtual_address']:08x}\n")
                    f.write(f"; Size: {len(instructions)} instructions\n")
                    f.write(f"; Raw Size: {len(section_data)} bytes\n\n")
                    
                    for inst in instructions:
                        f.write(f"0x{inst['address']:08x}: {inst['bytes']:<20} "
                               f"{inst['mnemonic']} {inst['op_str']}\n")
                
                files_created.append(asm_file)
                print(f"   ✅ Assembly: {os.path.basename(asm_file)}")
                
                # Fonksiyonları tespit et
                functions = self.identify_functions(instructions)
                print(f"   Functions: {len(functions)}")
                
                # C pseudocode oluştur
                if functions:
                    c_file = os.path.join(self.output_dir, f"{file_base}_{section_name}.c")
                    with open(c_file, 'w') as f:
                        f.write(f"// Pseudocode reconstruction of {section_name} section\n")
                        f.write(f"// Generated from: {self.file_path}\n")
                        f.write(f"// Original Address: 0x{section['virtual_address']:08x}\n\n")
                        f.write("#include <windows.h>\n\n")
                        
                        for func in functions:
                            f.write(self.generate_c_pseudocode(func))
                            f.write("\n")
                    
                    files_created.append(c_file)
                    print(f"   ✅ C Code: {os.path.basename(c_file)}")
                
                # Constants ve addresses çıkar
                constants, addresses = self.extract_constants_and_strings(instructions)
                
                if constants or addresses:
                    const_file = os.path.join(self.output_dir, f"{file_base}_{section_name}_constants.txt")
                    with open(const_file, 'w') as f:
                        f.write(f"Constants and Addresses from {section_name}\n")
                        f.write("=" * 50 + "\n\n")
                        
                        if constants:
                            f.write("CONSTANTS:\n")
                            for const in sorted(set(constants)):
                                f.write(f"  {const}\n")
                            f.write("\n")
                        
                        if addresses:
                            f.write("MEMORY ADDRESSES:\n")
                            for addr in sorted(set(addresses)):
                                f.write(f"  {addr}\n")
                    
                    files_created.append(const_file)
                    print(f"   ✅ Constants: {os.path.basename(const_file)}")
        
        # Entry point analizi
        if self.entry_point and self.code_sections:
            print(f"\n🎯 Entry Point Analysis: 0x{self.entry_point:08x}")
            
            # Entry point section'ını bul
            for section in self.code_sections:
                if (section['virtual_address'] <= self.entry_point < 
                    section['virtual_address'] + section['virtual_size']):
                    
                    offset_in_section = self.entry_point - section['virtual_address']
                    
                    if offset_in_section < len(section.get('data', b'')):
                        # Entry point etrafındaki 512 byte'ı disassemble et
                        start_offset = max(0, offset_in_section - 256)
                        end_offset = min(len(section['data']), offset_in_section + 256)
                        entry_data = section['data'][start_offset:end_offset]
                        
                        entry_instructions = self.disassemble_with_capstone(
                            entry_data, 
                            section['virtual_address'] + start_offset
                        )
                        
                        entry_file = os.path.join(self.output_dir, f"{file_base}_entry_point.asm")
                        with open(entry_file, 'w') as f:
                            f.write(f"; Entry Point Analysis\n")
                            f.write(f"; Entry Address: 0x{self.entry_point:08x}\n")
                            f.write(f"; Section: {section['name']}\n\n")
                            
                            for inst in entry_instructions:
                                marker = " <-- ENTRY POINT" if inst['address'] == self.entry_point else ""
                                f.write(f"0x{inst['address']:08x}: {inst['bytes']:<20} "
                                       f"{inst['mnemonic']} {inst['op_str']}{marker}\n")
                        
                        files_created.append(entry_file)
                        print(f"   ✅ Entry Point: {os.path.basename(entry_file)}")
                    break
        
        # Raw hex dump da ekle
        hex_file = os.path.join(self.output_dir, f"{file_base}_hexdump.txt")
        with open(hex_file, 'w') as f:
            f.write(f"Hex Dump of {os.path.basename(self.file_path)}\n")
            f.write("=" * 50 + "\n\n")
            
            # İlk 1024 byte
            for i in range(0, min(1024, len(self.file_data)), 16):
                line_data = self.file_data[i:i+16]
                hex_part = ' '.join(f'{b:02x}' for b in line_data)
                ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in line_data)
                f.write(f"{i:08x}: {hex_part:<48} |{ascii_part}|\n")
        
        files_created.append(hex_file)
        
        # Advanced decompilation - ORIGINAL SOURCE CODE RECONSTRUCTION
        print(f"\n🚀 ADVANCED DECOMPILATION BAŞLATILIYOR...")
        try:
            from tools.advanced_decompiler import AdvancedDecompiler
            decompiler = AdvancedDecompiler(self.file_path, self.output_dir)
            decompiled_files = decompiler.analyze_and_decompile()
            
            if decompiled_files:
                files_created.extend(decompiled_files)
                print(f"🎉 Original source code reconstructed!")
                for file_path in decompiled_files:
                    print(f"   🎯 {os.path.basename(file_path)}")
            else:
                print("⚠️  Source code reconstruction failed")
                
        except Exception as e:
            print(f"❌ Advanced decompilation error: {e}")
        
        # Assembly to Source Code Conversion
        print(f"\n🔄 ASSEMBLY TO SOURCE CODE CONVERSION...")
        try:
            from tools.asm_to_source_converter import AssemblyToSourceConverter
            
            # .asm dosyalarını bul ve çevir
            asm_files = [f for f in files_created if f.endswith('.asm')]
            converted_files = []
            
            for asm_file in asm_files:
                print(f"   Converting: {os.path.basename(asm_file)}")
                converter = AssemblyToSourceConverter(asm_file)
                result = converter.convert()
                
                if result:
                    converted_files.extend(result)
                    for converted in result:
                        print(f"   ✅ Generated: {os.path.basename(converted)}")
            
            if converted_files:
                files_created.extend(converted_files)
                print(f"🎉 Assembly conversion completed! Generated {len(converted_files)} source files")
            else:
                print("⚠️  No assembly files converted")
                
        except Exception as e:
            print(f"❌ Assembly conversion error: {e}")
        
        print(f"\n✅ Complete analysis finished!")
        print(f"📂 Output directory: {self.output_dir}")
        print(f"📄 Total files created: {len(files_created)}")
        
        # Kategorize files
        categories = {
            'Assembly Files': [f for f in files_created if f.endswith('.asm')],
            'Source Code': [f for f in files_created if f.endswith(('.py', '.cpp', '.cs', '.go', '.java', '.js'))],
            'C Pseudocode': [f for f in files_created if f.endswith('.c')],
            'Documentation': [f for f in files_created if f.endswith(('.txt', '.md'))],
            'Other': [f for f in files_created if not any(f.endswith(ext) for ext in ['.asm', '.py', '.cpp', '.cs', '.go', '.java', '.js', '.c', '.txt', '.md'])]
        }
        
        for category, category_files in categories.items():
            if category_files:
                print(f"\n📁 {category}:")
                for file_path in category_files:
                    print(f"   - {os.path.basename(file_path)}")
        
        return True

def main():
    if len(sys.argv) < 2:
        print("Kullanım: python disassembler.py <exe_dosyasi> [output_dir]")
        sys.exit(1)
    
    file_path = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else "extracted/source_code"
    
    if not os.path.exists(file_path):
        print(f"Dosya bulunamadı: {file_path}")
        sys.exit(1)
    
    disasm = AdvancedDisassembler(file_path, output_dir)
    disasm.disassemble_and_extract()

if __name__ == "__main__":
    main()