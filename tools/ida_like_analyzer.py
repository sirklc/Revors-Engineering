#!/usr/bin/env python3
"""
IDA-like Advanced Binary Analyzer
IDA Pro benzeri gelişmiş binary analiz araçları
"""

import sys
import os
import struct
import hashlib
from collections import defaultdict, OrderedDict
from datetime import datetime
import json
import re

try:
    import capstone
    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False

class IDALikeAnalyzer:
    def __init__(self, file_path):
        self.file_path = file_path
        self.file_data = None
        self.file_size = 0
        
        # PE Structure
        self.pe_offset = None
        self.entry_point = None
        self.image_base = 0x400000
        self.sections = []
        self.imports = defaultdict(list)
        self.exports = []
        
        # Analysis Data
        self.functions = OrderedDict()
        self.basic_blocks = {}
        self.xrefs = defaultdict(list)  # Cross-references
        self.strings = []
        self.comments = {}
        self.names = {}  # Address -> Name mapping
        
        # Disassembly
        self.instructions = {}  # Address -> Instruction
        self.data_refs = defaultdict(list)
        self.code_refs = defaultdict(list)
        
    def load_file(self):
        """Dosyayı yükle ve temel bilgileri al"""
        try:
            with open(self.file_path, 'rb') as f:
                self.file_data = f.read()
            self.file_size = len(self.file_data)
            return True
        except Exception as e:
            print(f"Dosya yüklenemedi: {e}")
            return False
    
    def parse_pe_headers(self):
        """PE header'larını parse et"""
        if self.file_size < 64 or self.file_data[:2] != b'MZ':
            return False
            
        # DOS Header
        self.pe_offset = struct.unpack('<I', self.file_data[60:64])[0]
        
        if (self.pe_offset >= self.file_size - 4 or 
            self.file_data[self.pe_offset:self.pe_offset+4] != b'PE\x00\x00'):
            return False
        
        # PE Header
        pe_header_offset = self.pe_offset + 4
        machine = struct.unpack('<H', self.file_data[pe_header_offset:pe_header_offset+2])[0]
        section_count = struct.unpack('<H', self.file_data[pe_header_offset+2:pe_header_offset+4])[0]
        
        # Optional Header
        opt_header_offset = self.pe_offset + 24
        if opt_header_offset + 28 <= self.file_size:
            self.entry_point = struct.unpack('<I', self.file_data[opt_header_offset+16:opt_header_offset+20])[0]
            self.image_base = struct.unpack('<I', self.file_data[opt_header_offset+28:opt_header_offset+32])[0]
        
        # Section Headers
        opt_header_size = struct.unpack('<H', self.file_data[self.pe_offset+20:self.pe_offset+22])[0]
        section_table_offset = self.pe_offset + 24 + opt_header_size
        
        for i in range(section_count):
            section_offset = section_table_offset + (i * 40)
            if section_offset + 40 > self.file_size:
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
            
            # Section permissions
            section['readable'] = bool(section['characteristics'] & 0x40000000)
            section['writable'] = bool(section['characteristics'] & 0x80000000)
            section['executable'] = bool(section['characteristics'] & 0x20000000)
            
            self.sections.append(section)
        
        return True
    
    def rva_to_file_offset(self, rva):
        """RVA'yı file offset'e çevir"""
        for section in self.sections:
            if (section['virtual_address'] <= rva < 
                section['virtual_address'] + section['virtual_size']):
                return section['pointer_to_raw_data'] + (rva - section['virtual_address'])
        return None
    
    def file_offset_to_rva(self, offset):
        """File offset'i RVA'ya çevir"""
        for section in self.sections:
            if (section['pointer_to_raw_data'] <= offset < 
                section['pointer_to_raw_data'] + section['size_of_raw_data']):
                return section['virtual_address'] + (offset - section['pointer_to_raw_data'])
        return None
    
    def get_section_at_rva(self, rva):
        """RVA'deki section'ı bul"""
        for section in self.sections:
            if (section['virtual_address'] <= rva < 
                section['virtual_address'] + section['virtual_size']):
                return section
        return None
    
    def disassemble_function(self, start_rva, max_instructions=1000):
        """Bir fonksiyonu disassemble et"""
        if not CAPSTONE_AVAILABLE:
            return []
        
        instructions = []
        visited = set()
        to_process = [start_rva]
        
        # x86-32 disassembler
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        md.detail = True
        
        while to_process and len(instructions) < max_instructions:
            current_rva = to_process.pop(0)
            
            if current_rva in visited:
                continue
            visited.add(current_rva)
            
            file_offset = self.rva_to_file_offset(current_rva)
            if not file_offset or file_offset >= self.file_size:
                continue
            
            # 32 byte'lık chunk oku
            chunk_size = min(32, self.file_size - file_offset)
            chunk = self.file_data[file_offset:file_offset + chunk_size]
            
            try:
                for insn in md.disasm(chunk, self.image_base + current_rva, 1):
                    inst_data = {
                        'address': insn.address,
                        'rva': current_rva,
                        'mnemonic': insn.mnemonic,
                        'op_str': insn.op_str,
                        'bytes': insn.bytes.hex(),
                        'size': insn.size,
                        'groups': insn.groups,
                        'operands': []
                    }
                    
                    # Operand analizi
                    for op in insn.operands:
                        op_data = {'type': op.type}
                        if op.type == capstone.x86.X86_OP_IMM:
                            op_data['imm'] = op.imm
                        elif op.type == capstone.x86.X86_OP_MEM:
                            op_data['mem'] = {
                                'base': op.mem.base,
                                'index': op.mem.index,
                                'disp': op.mem.disp
                            }
                        inst_data['operands'].append(op_data)
                    
                    instructions.append(inst_data)
                    self.instructions[current_rva] = inst_data
                    
                    # Control flow analizi
                    if insn.group(capstone.CS_GRP_JUMP):
                        # Jump instruction
                        if insn.operands and insn.operands[0].type == capstone.x86.X86_OP_IMM:
                            target_addr = insn.operands[0].imm
                            target_rva = target_addr - self.image_base
                            if target_rva not in visited:
                                to_process.append(target_rva)
                                self.code_refs[target_rva].append(current_rva)
                    
                    elif insn.group(capstone.CS_GRP_CALL):
                        # Call instruction
                        if insn.operands and insn.operands[0].type == capstone.x86.X86_OP_IMM:
                            target_addr = insn.operands[0].imm
                            target_rva = target_addr - self.image_base
                            self.code_refs[target_rva].append(current_rva)
                    
                    elif insn.group(capstone.CS_GRP_RET):
                        # Return instruction - stop following this path
                        break
                    
                    # Next instruction
                    current_rva += insn.size
                    break
                    
            except capstone.CsError as e:
                # Disassembly failed, skip
                break
        
        return instructions
    
    def identify_functions(self):
        """Fonksiyonları tespit et"""
        print("🔍 Function identification...")
        
        # Entry point'ten başla
        if self.entry_point:
            self.analyze_function(self.entry_point, f"start")
        
        # Export table'dan fonksiyonları bul
        # Import table'dan çağrılan adresleri bul
        
        # Code pattern'leri ara
        self.find_function_patterns()
        
        print(f"✅ {len(self.functions)} function identified")
    
    def analyze_function(self, rva, name=None):
        """Bir fonksiyonu analiz et"""
        if rva in self.functions:
            return self.functions[rva]
        
        if not name:
            name = f"sub_{rva:08x}"
        
        instructions = self.disassemble_function(rva)
        if not instructions:
            return None
        
        # Basic block analizi
        basic_blocks = self.analyze_basic_blocks(instructions)
        
        function_data = {
            'name': name,
            'rva': rva,
            'address': self.image_base + rva,
            'instructions': instructions,
            'basic_blocks': basic_blocks,
            'size': sum(inst['size'] for inst in instructions),
            'calls_to': [],
            'calls_from': [],
            'references': []
        }
        
        self.functions[rva] = function_data
        self.names[rva] = name
        
        return function_data
    
    def analyze_basic_blocks(self, instructions):
        """Basic block'ları analiz et"""
        if not instructions:
            return []
        
        basic_blocks = []
        current_block = []
        
        for inst in instructions:
            current_block.append(inst)
            
            # Block enders: jumps, calls, returns
            if (inst['mnemonic'] in ['jmp', 'je', 'jne', 'jz', 'jnz', 'ja', 'jb', 
                                   'jae', 'jbe', 'call', 'ret', 'retn']):
                if current_block:
                    basic_blocks.append({
                        'start_rva': current_block[0]['rva'],
                        'end_rva': current_block[-1]['rva'],
                        'instructions': current_block.copy()
                    })
                    current_block = []
        
        # Son block
        if current_block:
            basic_blocks.append({
                'start_rva': current_block[0]['rva'],
                'end_rva': current_block[-1]['rva'],
                'instructions': current_block
            })
        
        return basic_blocks
    
    def find_function_patterns(self):
        """Function pattern'lerini ara"""
        if not CAPSTONE_AVAILABLE:
            return
        
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        
        # Her executable section'ı tara
        for section in self.sections:
            if not section['executable']:
                continue
            
            print(f"  Scanning section: {section['name']}")
            
            section_start = section['pointer_to_raw_data']
            section_size = min(section['size_of_raw_data'], self.file_size - section_start)
            
            if section_size <= 0:
                continue
            
            section_data = self.file_data[section_start:section_start + section_size]
            base_rva = section['virtual_address']
            
            # Function prologue pattern'leri ara
            patterns = [
                b'\x55\x8b\xec',  # push ebp; mov ebp, esp
                b'\x55\x89\xe5',  # push ebp; mov ebp, esp (AT&T syntax)
                b'\x53\x55\x8b\xec',  # push ebx; push ebp; mov ebp, esp
            ]
            
            for pattern in patterns:
                offset = 0
                while True:
                    pos = section_data.find(pattern, offset)
                    if pos == -1:
                        break
                    
                    func_rva = base_rva + pos
                    if func_rva not in self.functions:
                        try:
                            self.analyze_function(func_rva)
                        except:
                            pass
                    
                    offset = pos + 1
    
    def extract_strings(self, min_length=4):
        """String'leri çıkar"""
        print("📝 String extraction...")
        
        # ASCII strings
        ascii_pattern = rb'[\x20-\x7E]{' + str(min_length).encode() + rb',}'
        ascii_matches = re.finditer(ascii_pattern, self.file_data)
        
        # Unicode strings (UTF-16LE)
        unicode_pattern = rb'(?:[\x20-\x7E]\x00){' + str(min_length).encode() + rb',}'
        unicode_matches = re.finditer(unicode_pattern, self.file_data)
        
        for match in ascii_matches:
            string_data = {
                'offset': match.start(),
                'rva': self.file_offset_to_rva(match.start()),
                'type': 'ascii',
                'value': match.group().decode('ascii', errors='ignore'),
                'length': len(match.group())
            }
            self.strings.append(string_data)
        
        for match in unicode_matches:
            string_data = {
                'offset': match.start(),
                'rva': self.file_offset_to_rva(match.start()),
                'type': 'unicode',
                'value': match.group().decode('utf-16le', errors='ignore'),
                'length': len(match.group()) // 2
            }
            self.strings.append(string_data)
        
        print(f"✅ {len(self.strings)} strings extracted")
    
    def analyze_cross_references(self):
        """Cross-reference analizi"""
        print("🔗 Cross-reference analysis...")
        
        # Her instruction için reference'ları analiz et
        for rva, inst in self.instructions.items():
            # Memory operand'ları kontrol et
            for op in inst.get('operands', []):
                if op['type'] == capstone.x86.X86_OP_MEM:
                    mem = op['mem']
                    if mem['base'] == 0 and mem['index'] == 0:  # Direct memory reference
                        target_addr = mem['disp']
                        target_rva = target_addr - self.image_base
                        if 0 <= target_rva < 0x10000000:  # Reasonable range
                            self.data_refs[target_rva].append(rva)
                            self.xrefs[target_rva].append({
                                'from': rva,
                                'type': 'data',
                                'instruction': inst
                            })
        
        print(f"✅ Cross-references analyzed")
    
    def generate_idb_like_data(self):
        """IDA database benzeri data yapısı oluştur"""
        return {
            'file_info': {
                'path': self.file_path,
                'size': self.file_size,
                'md5': hashlib.md5(self.file_data).hexdigest(),
                'sha256': hashlib.sha256(self.file_data).hexdigest(),
                'analysis_time': datetime.now().isoformat()
            },
            'pe_info': {
                'entry_point': self.entry_point,
                'image_base': self.image_base,
                'sections': self.sections
            },
            'functions': {hex(rva): func for rva, func in self.functions.items()},
            'strings': self.strings,
            'xrefs': {hex(rva): refs for rva, refs in self.xrefs.items() if refs},
            'names': {hex(rva): name for rva, name in self.names.items()},
            'comments': {hex(rva): comment for rva, comment in self.comments.items()}
        }
    
    def analyze(self):
        """Ana analiz fonksiyonu"""
        print(f"🔍 IDA-like Analysis: {os.path.basename(self.file_path)}")
        print("=" * 80)
        
        if not self.load_file():
            return False
        
        if not self.parse_pe_headers():
            print("❌ PE header parsing failed")
            return False
        
        print("✅ PE headers parsed")
        print(f"   Entry Point: 0x{self.entry_point:08x}")
        print(f"   Image Base: 0x{self.image_base:08x}")
        print(f"   Sections: {len(self.sections)}")
        
        # Function identification
        self.identify_functions()
        
        # String extraction
        self.extract_strings()
        
        # Cross-reference analysis
        self.analyze_cross_references()
        
        return True
    
    def save_analysis(self, output_path):
        """Analiz sonuçlarını kaydet"""
        data = self.generate_idb_like_data()
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False, default=str)
        
        print(f"✅ Analysis saved: {output_path}")
        return True

def main():
    if len(sys.argv) != 2:
        print("Usage: python ida_like_analyzer.py <exe_file>")
        sys.exit(1)
    
    file_path = sys.argv[1]
    if not os.path.exists(file_path):
        print(f"File not found: {file_path}")
        sys.exit(1)
    
    analyzer = IDALikeAnalyzer(file_path)
    if analyzer.analyze():
        # Save analysis
        base_name = os.path.splitext(os.path.basename(file_path))[0]
        output_path = f"{base_name}_ida_analysis.json"
        analyzer.save_analysis(output_path)
        
        # Print summary
        print(f"\n📊 ANALYSIS SUMMARY")
        print("=" * 50)
        print(f"Functions: {len(analyzer.functions)}")
        print(f"Strings: {len(analyzer.strings)}")
        print(f"Cross-refs: {sum(len(refs) for refs in analyzer.xrefs.values())}")

if __name__ == "__main__":
    main()