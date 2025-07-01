#!/usr/bin/env python3
"""
Interactive Hex Viewer
IDA benzeri hex viewer ve editor
"""

import sys
import os
import struct
from collections import defaultdict

class InteractiveHexViewer:
    def __init__(self, file_path):
        self.file_path = file_path
        self.file_data = None
        self.file_size = 0
        self.current_offset = 0
        self.bytes_per_line = 16
        self.annotations = {}  # offset -> annotation
        self.bookmarks = set()
        self.patches = {}  # offset -> original_byte
        
    def load_file(self):
        """Dosyayı yükle"""
        try:
            with open(self.file_path, 'rb') as f:
                self.file_data = bytearray(f.read())
            self.file_size = len(self.file_data)
            return True
        except Exception as e:
            print(f"Dosya yüklenemedi: {e}")
            return False
    
    def format_hex_line(self, offset, highlight_offset=None):
        """Hex line formatla"""
        if offset >= self.file_size:
            return ""
        
        # Read data for this line
        end_offset = min(offset + self.bytes_per_line, self.file_size)
        line_data = self.file_data[offset:end_offset]
        
        # Format address
        addr_str = f"{offset:08x}:"
        
        # Format hex bytes
        hex_parts = []
        for i, byte in enumerate(line_data):
            byte_offset = offset + i
            
            # Highlight if needed
            if byte_offset == highlight_offset:
                hex_parts.append(f"[{byte:02x}]")
            elif byte_offset in self.bookmarks:
                hex_parts.append(f"*{byte:02x}*")
            elif byte_offset in self.patches:
                hex_parts.append(f"!{byte:02x}!")
            else:
                hex_parts.append(f"{byte:02x}")
        
        # Pad hex section
        hex_str = " ".join(hex_parts)
        hex_str = hex_str.ljust(self.bytes_per_line * 3)
        
        # Format ASCII
        ascii_parts = []
        for i, byte in enumerate(line_data):
            byte_offset = offset + i
            
            if 32 <= byte <= 126:
                char = chr(byte)
            else:
                char = '.'
            
            # Highlight ASCII too
            if byte_offset == highlight_offset:
                ascii_parts.append(f"[{char}]")
            elif byte_offset in self.bookmarks:
                ascii_parts.append(f"*{char}*")
            elif byte_offset in self.patches:
                ascii_parts.append(f"!{char}!")
            else:
                ascii_parts.append(char)
        
        ascii_str = "".join(ascii_parts)
        
        # Annotation
        annotation = ""
        if offset in self.annotations:
            annotation = f" ; {self.annotations[offset]}"
        
        return f"{addr_str} {hex_str} |{ascii_str}|{annotation}"
    
    def display_hex_view(self, start_offset=None, lines=20):
        """Hex view göster"""
        if start_offset is None:
            start_offset = self.current_offset
        
        print(f"\n=== HEX VIEW: {os.path.basename(self.file_path)} ===")
        print(f"Offset: 0x{start_offset:08x} | Size: {self.file_size:,} bytes")
        print(f"Bookmarks: {len(self.bookmarks)} | Patches: {len(self.patches)}")
        print("-" * 80)
        
        for i in range(lines):
            line_offset = start_offset + (i * self.bytes_per_line)
            if line_offset >= self.file_size:
                break
            
            line = self.format_hex_line(line_offset, self.current_offset)
            print(line)
        
        print("-" * 80)
    
    def goto_offset(self, offset):
        """Offset'e git"""
        if 0 <= offset < self.file_size:
            self.current_offset = offset
            return True
        return False
    
    def search_bytes(self, pattern, start_offset=0):
        """Byte pattern ara"""
        if isinstance(pattern, str):
            # Hex string to bytes
            try:
                pattern = bytes.fromhex(pattern.replace(' ', ''))
            except ValueError:
                return []
        
        results = []
        offset = start_offset
        
        while offset < self.file_size:
            pos = self.file_data.find(pattern, offset)
            if pos == -1:
                break
            results.append(pos)
            offset = pos + 1
        
        return results
    
    def search_string(self, search_str, encoding='ascii'):
        """String ara"""
        results = []
        
        if encoding == 'ascii':
            pattern = search_str.encode('ascii', errors='ignore')
        elif encoding == 'unicode':
            pattern = search_str.encode('utf-16le', errors='ignore')
        else:
            return results
        
        offset = 0
        while offset < self.file_size:
            pos = self.file_data.find(pattern, offset)
            if pos == -1:
                break
            results.append(pos)
            offset = pos + 1
        
        return results
    
    def add_bookmark(self, offset=None):
        """Bookmark ekle"""
        if offset is None:
            offset = self.current_offset
        self.bookmarks.add(offset)
    
    def remove_bookmark(self, offset=None):
        """Bookmark sil"""
        if offset is None:
            offset = self.current_offset
        self.bookmarks.discard(offset)
    
    def add_annotation(self, text, offset=None):
        """Annotation ekle"""
        if offset is None:
            offset = self.current_offset
        self.annotations[offset] = text
    
    def patch_byte(self, new_value, offset=None):
        """Byte patch et"""
        if offset is None:
            offset = self.current_offset
        
        if 0 <= offset < self.file_size:
            if offset not in self.patches:
                self.patches[offset] = self.file_data[offset]
            self.file_data[offset] = new_value
            return True
        return False
    
    def undo_patch(self, offset=None):
        """Patch'i geri al"""
        if offset is None:
            offset = self.current_offset
        
        if offset in self.patches:
            self.file_data[offset] = self.patches[offset]
            del self.patches[offset]
            return True
        return False
    
    def save_patched_file(self, output_path):
        """Patch'lenmiş dosyayı kaydet"""
        try:
            with open(output_path, 'wb') as f:
                f.write(self.file_data)
            return True
        except Exception as e:
            print(f"Dosya kaydedilemedi: {e}")
            return False
    
    def analyze_data_at_offset(self, offset=None):
        """Offset'teki data'yı analiz et"""
        if offset is None:
            offset = self.current_offset
        
        if offset + 8 > self.file_size:
            return
        
        data = self.file_data[offset:offset+8]
        
        print(f"\n=== DATA ANALYSIS AT 0x{offset:08x} ===")
        print(f"Raw bytes: {' '.join(f'{b:02x}' for b in data[:8])}")
        
        # Different interpretations
        try:
            # Integers
            uint8 = data[0]
            int8 = struct.unpack('b', data[:1])[0]
            print(f"UINT8:  {uint8} (0x{uint8:02x})")
            print(f"INT8:   {int8}")
            
            if len(data) >= 2:
                uint16_le = struct.unpack('<H', data[:2])[0]
                uint16_be = struct.unpack('>H', data[:2])[0]
                int16_le = struct.unpack('<h', data[:2])[0]
                int16_be = struct.unpack('>h', data[:2])[0]
                print(f"UINT16 LE: {uint16_le} (0x{uint16_le:04x})")
                print(f"UINT16 BE: {uint16_be} (0x{uint16_be:04x})")
                print(f"INT16 LE:  {int16_le}")
                print(f"INT16 BE:  {int16_be}")
            
            if len(data) >= 4:
                uint32_le = struct.unpack('<I', data[:4])[0]
                uint32_be = struct.unpack('>I', data[:4])[0]
                int32_le = struct.unpack('<i', data[:4])[0]
                int32_be = struct.unpack('>i', data[:4])[0]
                float32_le = struct.unpack('<f', data[:4])[0]
                print(f"UINT32 LE: {uint32_le} (0x{uint32_le:08x})")
                print(f"UINT32 BE: {uint32_be} (0x{uint32_be:08x})")
                print(f"INT32 LE:  {int32_le}")
                print(f"INT32 BE:  {int32_be}")
                print(f"FLOAT LE:  {float32_le}")
            
            if len(data) >= 8:
                uint64_le = struct.unpack('<Q', data[:8])[0]
                int64_le = struct.unpack('<q', data[:8])[0]
                double_le = struct.unpack('<d', data[:8])[0]
                print(f"UINT64 LE: {uint64_le} (0x{uint64_le:016x})")
                print(f"INT64 LE:  {int64_le}")
                print(f"DOUBLE LE: {double_le}")
            
        except struct.error:
            pass
        
        # String interpretations
        ascii_str = data.decode('ascii', errors='ignore').rstrip('\x00')
        if ascii_str and all(32 <= ord(c) <= 126 for c in ascii_str):
            print(f"ASCII:     \"{ascii_str}\"")
        
        # Check if it looks like a pointer
        if len(data) >= 4:
            addr = struct.unpack('<I', data[:4])[0]
            if 0x400000 <= addr <= 0x500000:  # Common Windows executable range
                print(f"POINTER?:  0x{addr:08x}")
    
    def generate_hex_dump_html(self, output_path, start_offset=0, size=1024):
        """HTML hex dump oluştur"""
        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>Hex Dump - {os.path.basename(self.file_path)}</title>
    <style>
        body {{ font-family: 'Courier New', monospace; background: #1e1e1e; color: #d4d4d4; }}
        .hex-viewer {{ padding: 20px; }}
        .hex-line {{ margin: 2px 0; }}
        .address {{ color: #569cd6; }}
        .hex-byte {{ color: #b5cea8; }}
        .ascii {{ color: #ce9178; }}
        .bookmark {{ background-color: #264f78; }}
        .patch {{ background-color: #f14c4c; }}
        .annotation {{ color: #6a9955; font-style: italic; }}
    </style>
</head>
<body>
    <div class="hex-viewer">
        <h2>Hex Dump: {os.path.basename(self.file_path)}</h2>
        <p>Offset: 0x{start_offset:08x} | Size: {min(size, self.file_size - start_offset)} bytes</p>
        <hr>
"""
        
        end_offset = min(start_offset + size, self.file_size)
        
        for offset in range(start_offset, end_offset, self.bytes_per_line):
            line_data = self.file_data[offset:offset + self.bytes_per_line]
            
            # Address
            html_content += f'        <div class="hex-line">'
            html_content += f'<span class="address">{offset:08x}:</span> '
            
            # Hex bytes
            for i, byte in enumerate(line_data):
                byte_offset = offset + i
                css_class = "hex-byte"
                
                if byte_offset in self.bookmarks:
                    css_class += " bookmark"
                if byte_offset in self.patches:
                    css_class += " patch"
                
                html_content += f'<span class="{css_class}">{byte:02x}</span> '
            
            # Padding
            for i in range(self.bytes_per_line - len(line_data)):
                html_content += '   '
            
            # ASCII
            html_content += '|<span class="ascii">'
            for byte in line_data:
                if 32 <= byte <= 126:
                    html_content += chr(byte)
                else:
                    html_content += '.'
            html_content += '</span>|'
            
            # Annotation
            if offset in self.annotations:
                html_content += f' <span class="annotation">; {self.annotations[offset]}</span>'
            
            html_content += '</div>\n'
        
        html_content += """    </div>
</body>
</html>"""
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return True
    
    def interactive_mode(self):
        """Interactive mod"""
        print(f"🔍 Interactive Hex Viewer")
        print(f"File: {self.file_path}")
        print(f"Size: {self.file_size:,} bytes")
        print("\nCommands:")
        print("  g <offset>    - Goto offset (hex or decimal)")
        print("  /h <hex>      - Search hex pattern")
        print("  /s <string>   - Search ASCII string")
        print("  b             - Add bookmark at current offset")
        print("  B             - Remove bookmark")
        print("  a <text>      - Add annotation")
        print("  p <hex_byte>  - Patch byte at current offset")
        print("  u             - Undo patch")
        print("  d             - Analyze data at current offset")
        print("  l <lines>     - Display hex view (default 20 lines)")
        print("  save <file>   - Save patched file")
        print("  html <file>   - Export to HTML")
        print("  q             - Quit")
        
        while True:
            try:
                self.display_hex_view(lines=10)
                
                cmd = input(f"\n[{self.current_offset:08x}]> ").strip()
                if not cmd:
                    continue
                
                parts = cmd.split()
                cmd_name = parts[0].lower()
                
                if cmd_name == 'q':
                    break
                elif cmd_name == 'g' and len(parts) > 1:
                    try:
                        if parts[1].startswith('0x'):
                            offset = int(parts[1], 16)
                        else:
                            offset = int(parts[1])
                        if self.goto_offset(offset):
                            print(f"Moved to 0x{offset:08x}")
                        else:
                            print("Invalid offset")
                    except ValueError:
                        print("Invalid offset format")
                
                elif cmd_name == '/h' and len(parts) > 1:
                    pattern = ' '.join(parts[1:])
                    results = self.search_bytes(pattern)
                    print(f"Found {len(results)} matches:")
                    for i, pos in enumerate(results[:10]):
                        print(f"  {i+1}: 0x{pos:08x}")
                    if results:
                        self.goto_offset(results[0])
                
                elif cmd_name == '/s' and len(parts) > 1:
                    search_str = ' '.join(parts[1:])
                    results = self.search_string(search_str)
                    print(f"Found {len(results)} matches:")
                    for i, pos in enumerate(results[:10]):
                        print(f"  {i+1}: 0x{pos:08x}")
                    if results:
                        self.goto_offset(results[0])
                
                elif cmd_name == 'b':
                    self.add_bookmark()
                    print(f"Bookmark added at 0x{self.current_offset:08x}")
                
                elif cmd_name == 'B':
                    self.remove_bookmark()
                    print(f"Bookmark removed from 0x{self.current_offset:08x}")
                
                elif cmd_name == 'a' and len(parts) > 1:
                    annotation = ' '.join(parts[1:])
                    self.add_annotation(annotation)
                    print(f"Annotation added: {annotation}")
                
                elif cmd_name == 'p' and len(parts) > 1:
                    try:
                        new_value = int(parts[1], 16)
                        if 0 <= new_value <= 255:
                            self.patch_byte(new_value)
                            print(f"Patched byte at 0x{self.current_offset:08x} to 0x{new_value:02x}")
                        else:
                            print("Value must be 0-255")
                    except ValueError:
                        print("Invalid hex value")
                
                elif cmd_name == 'u':
                    if self.undo_patch():
                        print(f"Patch undone at 0x{self.current_offset:08x}")
                    else:
                        print("No patch to undo")
                
                elif cmd_name == 'd':
                    self.analyze_data_at_offset()
                
                elif cmd_name == 'l':
                    lines = 20
                    if len(parts) > 1:
                        try:
                            lines = int(parts[1])
                        except ValueError:
                            pass
                    self.display_hex_view(lines=lines)
                
                elif cmd_name == 'save' and len(parts) > 1:
                    output_path = parts[1]
                    if self.save_patched_file(output_path):
                        print(f"Saved to: {output_path}")
                    else:
                        print("Save failed")
                
                elif cmd_name == 'html' and len(parts) > 1:
                    output_path = parts[1]
                    if self.generate_hex_dump_html(output_path):
                        print(f"HTML exported to: {output_path}")
                    else:
                        print("HTML export failed")
                
                else:
                    print("Unknown command. Type 'q' to quit.")
                    
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"Error: {e}")

def main():
    if len(sys.argv) != 2:
        print("Usage: python hex_viewer.py <file>")
        sys.exit(1)
    
    file_path = sys.argv[1]
    if not os.path.exists(file_path):
        print(f"File not found: {file_path}")
        sys.exit(1)
    
    viewer = InteractiveHexViewer(file_path)
    if viewer.load_file():
        viewer.interactive_mode()

if __name__ == "__main__":
    main()