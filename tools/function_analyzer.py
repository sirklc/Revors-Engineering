#!/usr/bin/env python3
"""
Advanced Function Analyzer
IDA benzeri gelişmiş fonksiyon analizi
"""

import sys
import os
import struct
from collections import defaultdict, OrderedDict
import json
import hashlib

try:
    import capstone
    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False

class FunctionAnalyzer:
    def __init__(self, file_path):
        self.file_path = file_path
        self.file_data = None
        self.file_size = 0
        
        # PE Structure
        self.image_base = 0x400000
        self.entry_point = None
        self.sections = []
        
        # Functions
        self.functions = OrderedDict()
        self.function_signatures = {}
        self.function_hashes = {}
        
        # Analysis data
        self.basic_blocks = {}
        self.control_flow = defaultdict(list)
        self.api_calls = defaultdict(list)
        self.stack_analysis = {}
        
        # Patterns
        self.prologue_patterns = [
            b'\x55\x8b\xec',        # push ebp; mov ebp, esp
            b'\x55\x89\xe5',        # push ebp; mov ebp, esp (AT&T)
            b'\x53\x55\x8b\xec',    # push ebx; push ebp; mov ebp, esp
            b'\x56\x57\x55\x8b\xec', # push esi; push edi; push ebp; mov ebp, esp
            b'\x83\xec',            # sub esp, imm8
            b'\x81\xec',            # sub esp, imm32
        ]
        
        self.epilogue_patterns = [
            b'\x5d\xc3',            # pop ebp; ret
            b'\x89\xec\x5d\xc3',    # mov esp, ebp; pop ebp; ret
            b'\xc9\xc3',            # leave; ret
            b'\x5f\x5e\x5d\xc3',    # pop edi; pop esi; pop ebp; ret
        ]
    
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
    
    def parse_pe_headers(self):
        """PE headers parse et"""
        if self.file_size < 64 or self.file_data[:2] != b'MZ':
            return False
        
        pe_offset = struct.unpack('<I', self.file_data[60:64])[0]
        if (pe_offset >= self.file_size - 4 or 
            self.file_data[pe_offset:pe_offset+4] != b'PE\x00\x00'):
            return False
        
        # Entry point ve image base
        opt_header_offset = pe_offset + 24
        if opt_header_offset + 32 <= self.file_size:
            self.entry_point = struct.unpack('<I', self.file_data[opt_header_offset+16:opt_header_offset+20])[0]
            self.image_base = struct.unpack('<I', self.file_data[opt_header_offset+28:opt_header_offset+32])[0]
        
        # Sections
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
        """RVA to file offset"""
        for section in self.sections:
            if (section['virtual_address'] <= rva < 
                section['virtual_address'] + section['virtual_size']):
                return section['pointer_to_raw_data'] + (rva - section['virtual_address'])
        return None
    
    def find_function_starts_by_patterns(self):
        """Pattern'ler kullanarak function start'larını bul"""
        function_starts = set()
        
        # Entry point
        if self.entry_point:
            function_starts.add(self.entry_point)
        
        # Her executable section'da pattern ara
        for section in self.sections:
            if not section['executable']:
                continue
            
            section_start = section['pointer_to_raw_data']
            section_size = min(section['size_of_raw_data'], self.file_size - section_start)
            
            if section_size <= 0:
                continue
            
            section_data = self.file_data[section_start:section_start + section_size]
            base_rva = section['virtual_address']
            
            # Prologue pattern'leri ara
            for pattern in self.prologue_patterns:
                offset = 0
                while True:
                    pos = section_data.find(pattern, offset)
                    if pos == -1:
                        break
                    
                    func_rva = base_rva + pos
                    function_starts.add(func_rva)
                    offset = pos + 1
        
        return function_starts
    
    def analyze_function(self, start_rva, max_size=0x10000):
        """Bir fonksiyonu detaylı olarak analiz et"""
        if not CAPSTONE_AVAILABLE:
            return None
        
        # Disassemble function
        file_offset = self.rva_to_file_offset(start_rva)
        if not file_offset or file_offset >= self.file_size:
            return None
        
        # Function data oku
        func_size = min(max_size, self.file_size - file_offset)
        func_data = self.file_data[file_offset:file_offset + func_size]
        
        # Disassembler setup
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        md.detail = True
        
        instructions = []
        basic_blocks = []
        current_block = []
        api_calls = []
        local_vars = set()
        stack_usage = 0
        
        try:
            for insn in md.disasm(func_data, self.image_base + start_rva):
                inst_data = {
                    'address': insn.address,
                    'rva': insn.address - self.image_base,
                    'mnemonic': insn.mnemonic,
                    'op_str': insn.op_str,
                    'bytes': insn.bytes.hex(),
                    'size': insn.size
                }
                
                instructions.append(inst_data)
                current_block.append(inst_data)
                
                # Stack analysis
                if insn.mnemonic == 'push':
                    stack_usage += 4
                elif insn.mnemonic == 'pop':
                    stack_usage -= 4
                elif insn.mnemonic == 'sub' and 'esp' in insn.op_str:
                    # sub esp, value
                    try:
                        if 'esp,' in insn.op_str:
                            value_str = insn.op_str.split('esp,')[1].strip()
                            if value_str.startswith('0x'):
                                stack_usage += int(value_str, 16)
                            else:
                                stack_usage += int(value_str)
                    except:
                        pass
                elif insn.mnemonic == 'add' and 'esp' in insn.op_str:
                    # add esp, value
                    try:
                        if 'esp,' in insn.op_str:
                            value_str = insn.op_str.split('esp,')[1].strip()
                            if value_str.startswith('0x'):
                                stack_usage -= int(value_str, 16)
                            else:
                                stack_usage -= int(value_str)
                    except:
                        pass
                
                # Local variable access detection
                if '[ebp-' in insn.op_str or '[ebp+' in insn.op_str:
                    # Extract offset
                    import re
                    matches = re.findall(r'\[ebp([+-])0x([0-9a-fA-F]+)\]', insn.op_str)
                    for sign, offset_hex in matches:
                        offset = int(offset_hex, 16)
                        if sign == '-':
                            local_vars.add(-offset)
                        else:
                            local_vars.add(offset)
                
                # API call detection
                if insn.group(capstone.CS_GRP_CALL):
                    call_target = None
                    if insn.operands and insn.operands[0].type == capstone.x86.X86_OP_IMM:
                        call_target = insn.operands[0].imm
                    
                    api_calls.append({
                        'address': insn.address,
                        'target': call_target,
                        'instruction': f"{insn.mnemonic} {insn.op_str}"
                    })
                
                # Basic block boundaries
                if (insn.group(capstone.CS_GRP_JUMP) or 
                    insn.group(capstone.CS_GRP_CALL) or 
                    insn.group(capstone.CS_GRP_RET)):
                    
                    if current_block:
                        basic_blocks.append({
                            'start': current_block[0]['address'],
                            'end': current_block[-1]['address'],
                            'instructions': current_block.copy()
                        })
                        current_block = []
                    
                    # Function end on return
                    if insn.group(capstone.CS_GRP_RET):
                        break
        
        except capstone.CsError:
            pass
        
        # Son basic block
        if current_block:
            basic_blocks.append({
                'start': current_block[0]['address'],
                'end': current_block[-1]['address'],
                'instructions': current_block
            })
        
        if not instructions:
            return None
        
        # Function signature oluştur
        signature = self.generate_function_signature(instructions)
        
        # Function hash
        func_hash = self.calculate_function_hash(instructions)
        
        function_data = {
            'name': f'sub_{start_rva:08x}',
            'start_rva': start_rva,
            'start_address': self.image_base + start_rva,
            'size': sum(inst['size'] for inst in instructions),
            'instruction_count': len(instructions),
            'basic_blocks': basic_blocks,
            'basic_block_count': len(basic_blocks),
            'instructions': instructions,
            'api_calls': api_calls,
            'local_variables': sorted(local_vars),
            'stack_usage': stack_usage,
            'signature': signature,
            'hash': func_hash,
            'complexity': self.calculate_complexity(basic_blocks),
            'characteristics': self.analyze_function_characteristics(instructions)
        }
        
        return function_data
    
    def generate_function_signature(self, instructions):
        """Function signature oluştur (mnemonics based)"""
        mnemonics = [inst['mnemonic'] for inst in instructions[:20]]  # İlk 20 instruction
        return ' '.join(mnemonics)
    
    def calculate_function_hash(self, instructions):
        """Function hash hesapla"""
        # Instruction bytes'larını concat et
        all_bytes = b''.join(bytes.fromhex(inst['bytes']) for inst in instructions)
        return hashlib.md5(all_bytes).hexdigest()
    
    def calculate_complexity(self, basic_blocks):
        """Cyclomatic complexity hesapla"""
        # Basit approach: basic block sayısına dayalı
        edges = 0
        nodes = len(basic_blocks)
        
        # Her basic block için edge'leri say
        for block in basic_blocks:
            last_inst = block['instructions'][-1]
            if 'jmp' in last_inst['mnemonic'] or 'call' in last_inst['mnemonic']:
                edges += 1
            if last_inst['mnemonic'].startswith('j') and last_inst['mnemonic'] != 'jmp':
                edges += 1  # Conditional jump - 2 edges
        
        # Cyclomatic complexity = E - N + 2P (P=1 for single connected component)
        complexity = max(1, edges - nodes + 2)
        return complexity
    
    def analyze_function_characteristics(self, instructions):
        """Function karakteristiklerini analiz et"""
        characteristics = {
            'has_loops': False,
            'has_recursion': False,
            'has_function_calls': False,
            'has_string_refs': False,
            'uses_crypto': False,
            'uses_network': False,
            'uses_filesystem': False
        }
        
        for inst in instructions:
            # Function calls
            if inst['mnemonic'] == 'call':
                characteristics['has_function_calls'] = True
            
            # String references
            if 'offset' in inst['op_str'] or 'asc_' in inst['op_str']:
                characteristics['has_string_refs'] = True
            
            # Crypto patterns
            crypto_mnemonics = ['xor', 'rol', 'ror', 'shl', 'shr']
            if inst['mnemonic'] in crypto_mnemonics:
                characteristics['uses_crypto'] = True
            
            # Network/filesystem hints (basic)
            if any(api in inst['op_str'].lower() for api in 
                   ['socket', 'send', 'recv', 'connect', 'wsastartup']):
                characteristics['uses_network'] = True
            
            if any(api in inst['op_str'].lower() for api in 
                   ['createfile', 'readfile', 'writefile', 'findfile']):
                characteristics['uses_filesystem'] = True
        
        return characteristics
    
    def find_similar_functions(self, target_func):
        """Benzer fonksiyonları bul"""
        similar = []
        target_hash = target_func['hash']
        target_sig = target_func['signature']
        
        for rva, func in self.functions.items():
            if rva == target_func['start_rva']:
                continue
            
            # Hash match
            if func['hash'] == target_hash:
                similar.append({
                    'rva': rva,
                    'similarity': 1.0,
                    'match_type': 'hash_exact'
                })
                continue
            
            # Signature similarity
            sig_similarity = self.calculate_signature_similarity(target_sig, func['signature'])
            if sig_similarity > 0.8:
                similar.append({
                    'rva': rva,
                    'similarity': sig_similarity,
                    'match_type': 'signature_similar'
                })
        
        return sorted(similar, key=lambda x: x['similarity'], reverse=True)
    
    def calculate_signature_similarity(self, sig1, sig2):
        """Signature similarity hesapla"""
        words1 = set(sig1.split())
        words2 = set(sig2.split())
        
        if not words1 and not words2:
            return 1.0
        if not words1 or not words2:
            return 0.0
        
        intersection = len(words1.intersection(words2))
        union = len(words1.union(words2))
        
        return intersection / union if union > 0 else 0.0
    
    def analyze_all_functions(self):
        """Tüm fonksiyonları analiz et"""
        print("🎯 Finding function starts...")
        function_starts = self.find_function_starts_by_patterns()
        
        print(f"   Found {len(function_starts)} potential function starts")
        
        print("🔍 Analyzing functions...")
        analyzed_count = 0
        
        for start_rva in sorted(function_starts):
            func_data = self.analyze_function(start_rva)
            if func_data:
                self.functions[start_rva] = func_data
                analyzed_count += 1
                
                if analyzed_count % 10 == 0:
                    print(f"   Analyzed {analyzed_count} functions...")
        
        print(f"✅ {len(self.functions)} functions analyzed successfully")
    
    def generate_function_report(self):
        """Function analiz raporu oluştur"""
        report = {
            'file_info': {
                'path': os.path.basename(self.file_path),
                'size': self.file_size,
                'entry_point': f"0x{self.entry_point:08x}" if self.entry_point else None,
                'image_base': f"0x{self.image_base:08x}"
            },
            'statistics': {
                'total_functions': len(self.functions),
                'total_instructions': sum(f['instruction_count'] for f in self.functions.values()),
                'total_basic_blocks': sum(f['basic_block_count'] for f in self.functions.values()),
                'average_function_size': 0,
                'average_complexity': 0
            },
            'functions': {},
            'function_signatures': {},
            'similar_functions': {}
        }
        
        if self.functions:
            report['statistics']['average_function_size'] = sum(f['size'] for f in self.functions.values()) / len(self.functions)
            report['statistics']['average_complexity'] = sum(f['complexity'] for f in self.functions.values()) / len(self.functions)
        
        # Function details
        for rva, func in self.functions.items():
            addr_str = f"0x{rva:08x}"
            
            # Basic function info
            report['functions'][addr_str] = {
                'name': func['name'],
                'address': f"0x{func['start_address']:08x}",
                'size': func['size'],
                'instruction_count': func['instruction_count'],
                'basic_block_count': func['basic_block_count'],
                'complexity': func['complexity'],
                'stack_usage': func['stack_usage'],
                'local_variables': func['local_variables'],
                'api_calls': len(func['api_calls']),
                'characteristics': func['characteristics'],
                'hash': func['hash']
            }
            
            # Function signature
            report['function_signatures'][addr_str] = func['signature']
            
            # Similar functions
            similar = self.find_similar_functions(func)
            if similar:
                report['similar_functions'][addr_str] = similar[:5]  # Top 5
        
        return report
    
    def analyze(self):
        """Ana analiz fonksiyonu"""
        print(f"🎯 Function Analysis: {os.path.basename(self.file_path)}")
        print("=" * 80)
        
        if not self.load_file():
            return False
        
        if not self.parse_pe_headers():
            print("❌ PE parsing failed")
            return False
        
        print("✅ PE headers parsed")
        print(f"   Entry Point: 0x{self.entry_point:08x}")
        print(f"   Image Base: 0x{self.image_base:08x}")
        print(f"   Sections: {len(self.sections)}")
        
        # Function analysis
        self.analyze_all_functions()
        
        if self.functions:
            # Print top functions by size
            print(f"\n📊 TOP FUNCTIONS BY SIZE")
            sorted_funcs = sorted(self.functions.items(), key=lambda x: x[1]['size'], reverse=True)
            for i, (rva, func) in enumerate(sorted_funcs[:10]):
                print(f"   {i+1}. {func['name']} - {func['size']} bytes, {func['instruction_count']} instructions")
            
            # Print statistics
            avg_size = sum(f['size'] for f in self.functions.values()) / len(self.functions)
            avg_complexity = sum(f['complexity'] for f in self.functions.values()) / len(self.functions)
            
            print(f"\n📈 STATISTICS")
            print(f"   Average Function Size: {avg_size:.1f} bytes")
            print(f"   Average Complexity: {avg_complexity:.1f}")
            print(f"   Total Instructions: {sum(f['instruction_count'] for f in self.functions.values())}")
        
        return True
    
    def save_report(self, output_path):
        """Raporu kaydet"""
        report = self.generate_function_report()
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        print(f"✅ Function analysis report saved: {output_path}")
        return True

def main():
    if len(sys.argv) != 2:
        print("Usage: python function_analyzer.py <exe_file>")
        sys.exit(1)
    
    file_path = sys.argv[1]
    if not os.path.exists(file_path):
        print(f"File not found: {file_path}")
        sys.exit(1)
    
    analyzer = FunctionAnalyzer(file_path)
    if analyzer.analyze():
        # Save report
        base_name = os.path.splitext(os.path.basename(file_path))[0]
        output_path = f"{base_name}_functions.json"
        analyzer.save_report(output_path)

if __name__ == "__main__":
    main()