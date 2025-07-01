#!/usr/bin/env python3
"""
Cross-Reference Analyzer
IDA benzeri cross-reference analizi
"""

import sys
import os
import struct
from collections import defaultdict, OrderedDict
import json

try:
    import capstone
    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False

class XRefAnalyzer:
    def __init__(self, file_path):
        self.file_path = file_path
        self.file_data = None
        self.file_size = 0
        
        # PE Info
        self.image_base = 0x400000
        self.sections = []
        self.entry_point = None
        
        # Cross-references
        self.code_xrefs = defaultdict(list)  # target -> [source1, source2, ...]
        self.data_xrefs = defaultdict(list)  # target -> [source1, source2, ...]
        self.string_xrefs = defaultdict(list)  # string_offset -> [ref1, ref2, ...]
        
        # Functions and calls
        self.functions = {}
        self.function_calls = defaultdict(list)  # caller -> [callee1, callee2, ...]
        self.function_callers = defaultdict(list)  # callee -> [caller1, caller2, ...]
        
        # Strings and data
        self.strings = {}  # offset -> string_data
        self.data_locations = set()
        
        # Instructions
        self.instructions = {}  # address -> instruction_data
    
    def load_file(self):
        """Dosyayı yükle"""
        try:
            with open(self.file_path, 'rb') as f:
                self.file_data = f.read()
            self.file_size = len(self.file_data)
            return True
        except Exception as e:
            print(f"File load error: {e}")
            return False
    
    def parse_pe_basic(self):
        """Temel PE parsing"""
        if self.file_size < 64 or self.file_data[:2] != b'MZ':
            return False
        
        pe_offset = struct.unpack('<I', self.file_data[60:64])[0]
        if (pe_offset >= self.file_size - 4 or 
            self.file_data[pe_offset:pe_offset+4] != b'PE\x00\x00'):
            return False
        
        # Optional header'dan entry point ve image base al
        opt_header_offset = pe_offset + 24
        if opt_header_offset + 32 <= self.file_size:
            self.entry_point = struct.unpack('<I', self.file_data[opt_header_offset+16:opt_header_offset+20])[0]
            self.image_base = struct.unpack('<I', self.file_data[opt_header_offset+28:opt_header_offset+32])[0]
        
        # Section'ları parse et
        section_count = struct.unpack('<H', self.file_data[pe_offset+6:pe_offset+8])[0]
        opt_header_size = struct.unpack('<H', self.file_data[pe_offset+20:pe_offset+22])[0]
        section_table_offset = pe_offset + 24 + opt_header_size
        
        for i in range(section_count):
            section_offset = section_table_offset + (i * 40)
            if section_offset + 40 > self.file_size:
                break
            
            section_data = self.file_data[section_offset:section_offset+40]
            section = {
                'name': section_data[:8].rstrip(b'\x00').decode('ascii', errors='ignore'),
                'virtual_address': struct.unpack('<I', section_data[12:16])[0],
                'virtual_size': struct.unpack('<I', section_data[8:12])[0],
                'pointer_to_raw_data': struct.unpack('<I', section_data[20:24])[0],
                'size_of_raw_data': struct.unpack('<I', section_data[16:20])[0],
                'characteristics': struct.unpack('<I', section_data[36:40])[0]
            }
            
            section['executable'] = bool(section['characteristics'] & 0x20000000)
            section['readable'] = bool(section['characteristics'] & 0x40000000)
            section['writable'] = bool(section['characteristics'] & 0x80000000)
            
            self.sections.append(section)
        
        return True
    
    def rva_to_file_offset(self, rva):
        """RVA'yı file offset'e çevir"""
        for section in self.sections:
            if (section['virtual_address'] <= rva < 
                section['virtual_address'] + section['virtual_size']):
                return section['pointer_to_raw_data'] + (rva - section['virtual_address'])
        return None
    
    def is_valid_address(self, addr):
        """Adresin geçerli olup olmadığını kontrol et"""
        if addr < self.image_base:
            return False
        
        rva = addr - self.image_base
        for section in self.sections:
            if (section['virtual_address'] <= rva < 
                section['virtual_address'] + section['virtual_size']):
                return True
        return False
    
    def extract_strings(self, min_length=4):
        """String'leri çıkar ve cross-reference analizi için hazırla"""
        import re
        
        # ASCII strings
        ascii_pattern = rb'[\x20-\x7E]{' + str(min_length).encode() + rb',}'
        for match in re.finditer(ascii_pattern, self.file_data):
            self.strings[match.start()] = {
                'type': 'ascii',
                'value': match.group().decode('ascii', errors='ignore'),
                'offset': match.start(),
                'size': len(match.group())
            }
        
        # Unicode strings (UTF-16LE)
        unicode_pattern = rb'(?:[\x20-\x7E]\x00){' + str(min_length).encode() + rb',}'
        for match in re.finditer(unicode_pattern, self.file_data):
            try:
                unicode_str = match.group().decode('utf-16le', errors='ignore')
                self.strings[match.start()] = {
                    'type': 'unicode',
                    'value': unicode_str,
                    'offset': match.start(),
                    'size': len(match.group())
                }
            except:
                pass
    
    def disassemble_section(self, section):
        """Bir section'ı disassemble et ve xref analizi yap"""
        if not CAPSTONE_AVAILABLE or not section['executable']:
            return
        
        section_start = section['pointer_to_raw_data']
        section_size = min(section['size_of_raw_data'], self.file_size - section_start)
        
        if section_size <= 0:
            return
        
        section_data = self.file_data[section_start:section_start + section_size]
        base_rva = section['virtual_address']
        
        # Capstone disassembler
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        md.detail = True
        
        try:
            for insn in md.disasm(section_data, self.image_base + base_rva):
                inst_rva = insn.address - self.image_base
                
                # Instruction data kaydet
                self.instructions[inst_rva] = {
                    'address': insn.address,
                    'rva': inst_rva,
                    'mnemonic': insn.mnemonic,
                    'op_str': insn.op_str,
                    'size': insn.size,
                    'bytes': insn.bytes.hex()
                }
                
                # Cross-reference analizi
                self.analyze_instruction_xrefs(insn, inst_rva)
                
        except capstone.CsError as e:
            print(f"Disassembly error in section {section['name']}: {e}")
    
    def analyze_instruction_xrefs(self, insn, inst_rva):
        """Instruction'daki cross-reference'ları analiz et"""
        # Call instructions
        if insn.group(capstone.CS_GRP_CALL):
            for op in insn.operands:
                if op.type == capstone.x86.X86_OP_IMM:
                    target_addr = op.imm
                    if self.is_valid_address(target_addr):
                        target_rva = target_addr - self.image_base
                        self.code_xrefs[target_rva].append({
                            'from': inst_rva,
                            'type': 'call',
                            'instruction': f"{insn.mnemonic} {insn.op_str}"
                        })
                        
                        # Function call tracking
                        self.function_calls[inst_rva].append(target_rva)
                        self.function_callers[target_rva].append(inst_rva)
        
        # Jump instructions
        elif insn.group(capstone.CS_GRP_JUMP):
            for op in insn.operands:
                if op.type == capstone.x86.X86_OP_IMM:
                    target_addr = op.imm
                    if self.is_valid_address(target_addr):
                        target_rva = target_addr - self.image_base
                        
                        jump_type = 'jmp' if insn.mnemonic == 'jmp' else 'conditional_jump'
                        self.code_xrefs[target_rva].append({
                            'from': inst_rva,
                            'type': jump_type,
                            'instruction': f"{insn.mnemonic} {insn.op_str}"
                        })
        
        # Data references
        for op in insn.operands:
            if op.type == capstone.x86.X86_OP_MEM:
                # Direct memory reference [0x12345678]
                if op.mem.base == 0 and op.mem.index == 0 and op.mem.disp != 0:
                    target_addr = op.mem.disp
                    if self.is_valid_address(target_addr):
                        target_rva = target_addr - self.image_base
                        
                        self.data_xrefs[target_rva].append({
                            'from': inst_rva,
                            'type': 'data_ref',
                            'instruction': f"{insn.mnemonic} {insn.op_str}",
                            'access_type': self.get_memory_access_type(insn)
                        })
                        
                        # String reference check
                        file_offset = self.rva_to_file_offset(target_rva)
                        if file_offset and file_offset in self.strings:
                            self.string_xrefs[file_offset].append({
                                'from': inst_rva,
                                'type': 'string_ref',
                                'instruction': f"{insn.mnemonic} {insn.op_str}"
                            })
            
            # Immediate values that look like addresses
            elif op.type == capstone.x86.X86_OP_IMM:
                if self.is_valid_address(op.imm):
                    target_rva = op.imm - self.image_base
                    self.data_xrefs[target_rva].append({
                        'from': inst_rva,
                        'type': 'immediate_ref',
                        'instruction': f"{insn.mnemonic} {insn.op_str}"
                    })
    
    def get_memory_access_type(self, insn):
        """Memory access type'ını belirle"""
        if insn.mnemonic.startswith('mov'):
            # MOV instruction - determine direction
            if '[' in insn.op_str.split(',')[0]:
                return 'write'  # mov [mem], reg
            else:
                return 'read'   # mov reg, [mem]
        elif insn.mnemonic in ['push', 'lea']:
            return 'read'
        elif insn.mnemonic in ['pop']:
            return 'write'
        elif insn.mnemonic.startswith('cmp'):
            return 'read'
        else:
            return 'unknown'
    
    def find_function_starts(self):
        """Function start'larını bul"""
        # Entry point
        if self.entry_point:
            self.functions[self.entry_point] = {
                'name': 'start',
                'type': 'entry_point'
            }
        
        # Call target'ları
        for target_rva, refs in self.code_xrefs.items():
            for ref in refs:
                if ref['type'] == 'call':
                    self.functions[target_rva] = {
                        'name': f'sub_{target_rva:08x}',
                        'type': 'function'
                    }
    
    def analyze_function_relationships(self):
        """Function relationship'lerini analiz et"""
        print("🔗 Analyzing function relationships...")
        
        for func_rva in self.functions:
            # Bu fonksiyonu çağıran fonksiyonlar
            callers = []
            for caller_rva in self.function_callers.get(func_rva, []):
                # Caller'ın hangi fonksiyona ait olduğunu bul
                caller_func = self.find_function_containing_address(caller_rva)
                if caller_func and caller_func != func_rva:
                    callers.append(caller_func)
            
            # Bu fonksiyonun çağırdığı fonksiyonlar
            callees = self.function_calls.get(func_rva, [])
            
            if func_rva in self.functions:
                self.functions[func_rva]['callers'] = list(set(callers))
                self.functions[func_rva]['callees'] = callees
    
    def find_function_containing_address(self, rva):
        """Verilen RVA'yı içeren fonksiyonu bul"""
        # Basit approach: en yakın function start'ı bul
        best_func = None
        best_distance = float('inf')
        
        for func_rva in self.functions:
            if func_rva <= rva:
                distance = rva - func_rva
                if distance < best_distance and distance < 0x1000:  # Max 4KB function size
                    best_distance = distance
                    best_func = func_rva
        
        return best_func
    
    def generate_xref_report(self):
        """Cross-reference raporu oluştur"""
        report = {
            'file_info': {
                'path': os.path.basename(self.file_path),
                'size': self.file_size,
                'entry_point': f"0x{self.entry_point:08x}" if self.entry_point else None,
                'image_base': f"0x{self.image_base:08x}"
            },
            'sections': [],
            'functions': {},
            'code_xrefs': {},
            'data_xrefs': {},
            'string_xrefs': {},
            'statistics': {}
        }
        
        # Sections
        for section in self.sections:
            report['sections'].append({
                'name': section['name'],
                'virtual_address': f"0x{section['virtual_address']:08x}",
                'size': section['virtual_size'],
                'characteristics': {
                    'executable': section['executable'],
                    'readable': section['readable'],
                    'writable': section['writable']
                }
            })
        
        # Functions
        for rva, func_data in self.functions.items():
            report['functions'][f"0x{rva:08x}"] = {
                'name': func_data['name'],
                'type': func_data['type'],
                'callers': [f"0x{c:08x}" for c in func_data.get('callers', [])],
                'callees': [f"0x{c:08x}" for c in func_data.get('callees', [])]
            }
        
        # Code cross-references
        for rva, refs in self.code_xrefs.items():
            if refs:  # Only include if there are references
                report['code_xrefs'][f"0x{rva:08x}"] = [
                    {
                        'from': f"0x{ref['from']:08x}",
                        'type': ref['type'],
                        'instruction': ref['instruction']
                    } for ref in refs
                ]
        
        # Data cross-references
        for rva, refs in self.data_xrefs.items():
            if refs:
                report['data_xrefs'][f"0x{rva:08x}"] = [
                    {
                        'from': f"0x{ref['from']:08x}",
                        'type': ref['type'],
                        'instruction': ref['instruction'],
                        'access_type': ref.get('access_type', 'unknown')
                    } for ref in refs
                ]
        
        # String cross-references
        for offset, refs in self.string_xrefs.items():
            if refs and offset in self.strings:
                string_data = self.strings[offset]
                report['string_xrefs'][f"0x{offset:08x}"] = {
                    'string': string_data['value'][:100],  # Limit string length
                    'type': string_data['type'],
                    'references': [
                        {
                            'from': f"0x{ref['from']:08x}",
                            'type': ref['type'],
                            'instruction': ref['instruction']
                        } for ref in refs
                    ]
                }
        
        # Statistics
        report['statistics'] = {
            'total_functions': len(self.functions),
            'total_code_xrefs': sum(len(refs) for refs in self.code_xrefs.values()),
            'total_data_xrefs': sum(len(refs) for refs in self.data_xrefs.values()),
            'total_string_xrefs': sum(len(refs) for refs in self.string_xrefs.values()),
            'total_strings': len(self.strings)
        }
        
        return report
    
    def analyze(self):
        """Ana analiz fonksiyonu"""
        print(f"🔍 Cross-Reference Analysis: {os.path.basename(self.file_path)}")
        print("=" * 80)
        
        if not self.load_file():
            return False
        
        if not self.parse_pe_basic():
            print("❌ PE parsing failed")
            return False
        
        print("✅ PE parsed successfully")
        print(f"   Sections: {len(self.sections)}")
        print(f"   Entry Point: 0x{self.entry_point:08x}")
        
        # String extraction
        print("📝 Extracting strings...")
        self.extract_strings()
        print(f"✅ {len(self.strings)} strings found")
        
        # Disassemble executable sections
        print("🔍 Disassembling and analyzing cross-references...")
        for section in self.sections:
            if section['executable']:
                print(f"   Processing section: {section['name']}")
                self.disassemble_section(section)
        
        print(f"✅ {len(self.instructions)} instructions analyzed")
        
        # Function analysis
        print("🎯 Identifying functions...")
        self.find_function_starts()
        self.analyze_function_relationships()
        
        # Print summary
        print(f"\n📊 ANALYSIS SUMMARY")
        print("=" * 50)
        print(f"Functions: {len(self.functions)}")
        print(f"Code XRefs: {sum(len(refs) for refs in self.code_xrefs.values())}")
        print(f"Data XRefs: {sum(len(refs) for refs in self.data_xrefs.values())}")
        print(f"String XRefs: {sum(len(refs) for refs in self.string_xrefs.values())}")
        
        return True
    
    def save_report(self, output_path):
        """Raporu dosyaya kaydet"""
        report = self.generate_xref_report()
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        print(f"✅ Cross-reference report saved: {output_path}")
        return True

def main():
    if len(sys.argv) != 2:
        print("Usage: python xref_analyzer.py <exe_file>")
        sys.exit(1)
    
    file_path = sys.argv[1]
    if not os.path.exists(file_path):
        print(f"File not found: {file_path}")
        sys.exit(1)
    
    analyzer = XRefAnalyzer(file_path)
    if analyzer.analyze():
        # Save report
        base_name = os.path.splitext(os.path.basename(file_path))[0]
        output_path = f"{base_name}_xrefs.json"
        analyzer.save_report(output_path)

if __name__ == "__main__":
    main()