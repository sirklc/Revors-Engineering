#!/usr/bin/env python3
"""
Master Extractor
Tüm extraction araçlarını koordine eden ana kontrol scripti
"""

import sys
import os
import subprocess
import time
from pathlib import Path

class MasterExtractor:
    def __init__(self, file_path, output_base="extracted"):
        self.file_path = file_path
        self.output_base = output_base
        self.file_name = os.path.splitext(os.path.basename(file_path))[0]
        self.timestamp = time.strftime("%Y%m%d_%H%M%S")
        self.session_dir = os.path.join(output_base, f"{self.file_name}_{self.timestamp}")
        
        # Çıktı dizinleri
        self.output_dirs = {
            'source_code': os.path.join(self.session_dir, 'source_code'),
            'certificates': os.path.join(self.session_dir, 'certificates'),
            'dumps': os.path.join(self.session_dir, 'dumps'),
            'reconstructed': os.path.join(self.session_dir, 'reconstructed'),
            'resources': os.path.join(self.session_dir, 'resources'),
            'reports': os.path.join(self.session_dir, 'reports')
        }
        
        self.create_directories()
        
    def create_directories(self):
        """Tüm çıktı dizinlerini oluştur"""
        for dir_path in self.output_dirs.values():
            os.makedirs(dir_path, exist_ok=True)
    
    def run_tool(self, tool_name, tool_script, output_dir, description):
        """Bir analiz aracını çalıştır"""
        print(f"🔄 {description}")
        print(f"   Tool: {tool_script}")
        print(f"   Output: {output_dir}")
        
        try:
            cmd = ['python3', f'tools/{tool_script}', self.file_path, output_dir]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                print(f"   ✅ {tool_name} başarılı")
                return True, result.stdout
            else:
                print(f"   ❌ {tool_name} hatası: {result.stderr}")
                return False, result.stderr
                
        except subprocess.TimeoutExpired:
            print(f"   ⏰ {tool_name} timeout (5 dakika)")
            return False, "Timeout"
        except Exception as e:
            print(f"   💥 {tool_name} exception: {e}")
            return False, str(e)
    
    def extract_all(self):
        """Tüm extraction işlemlerini sırayla yap"""
        print(f"🚀 MASTER EXTRACTION SESSION")
        print("=" * 80)
        print(f"📁 Source File: {self.file_path}")
        print(f"📂 Session Directory: {self.session_dir}")
        print(f"🕐 Started: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        print()
        
        extraction_tools = [
            {
                'name': 'Language Detector',
                'script': 'language_detector.py',
                'output': self.output_dirs['source_code'],
                'description': 'Programming language detection'
            },
            {
                'name': 'Advanced Decompiler',
                'script': 'disassembler.py',
                'output': self.output_dirs['source_code'],
                'description': 'Advanced source code reconstruction'
            },
            {
                'name': 'Certificate Extractor',
                'script': 'certificate_extractor.py', 
                'output': self.output_dirs['certificates'],
                'description': 'Dijital sertifika analizi'
            },
            {
                'name': 'Memory Dump Analyzer',
                'script': 'memory_dump_analyzer.py',
                'output': self.output_dirs['dumps'],
                'description': 'Memory dump ve embedded PE analizi'
            },
            {
                'name': 'File Reconstructor',
                'script': 'file_reconstructor.py',
                'output': self.output_dirs['reconstructed'],
                'description': 'Dosya yapısı reconstruction'
            },
            {
                'name': 'Resource Extractor',
                'script': 'resource_extractor.py',
                'output': self.output_dirs['resources'],
                'description': 'Icon, string ve resource çıkarma'
            }
        ]
        
        results = {}
        total_tools = len(extraction_tools)
        
        for i, tool in enumerate(extraction_tools):
            print(f"[{i+1}/{total_tools}] {tool['description']}")
            success, output = self.run_tool(
                tool['name'], 
                tool['script'], 
                tool['output'], 
                tool['description']
            )
            
            results[tool['name']] = {
                'success': success,
                'output': output,
                'output_dir': tool['output']
            }
            print()
        
        # Assembly to Source Code Conversion - Final Step
        print(f"\n🔄 FINAL ASSEMBLY TO SOURCE CONVERSION...")
        try:
            from tools.asm_to_source_converter import convert_all_asm_files
            
            # Tüm çıktı dizinlerinde .asm dosyalarını bul ve çevir
            all_converted = []
            for dir_name, dir_path in self.output_dirs.items():
                if os.path.exists(dir_path):
                    converted_files = convert_all_asm_files(dir_path)
                    if converted_files:
                        all_converted.extend(converted_files)
                        print(f"   ✅ {dir_name}: {len(converted_files)} files converted")
            
            if all_converted:
                print(f"🎉 Total Assembly Conversion: {len(all_converted)} source files generated")
                results['Assembly to Source Converter'] = {
                    'success': True,
                    'output': f"Generated {len(all_converted)} source files",
                    'output_dir': self.session_dir
                }
            else:
                print("⚠️  No assembly files found to convert")
                results['Assembly to Source Converter'] = {
                    'success': False,
                    'output': "No .asm files found",
                    'output_dir': self.session_dir
                }
                
        except Exception as e:
            print(f"❌ Assembly conversion error: {e}")
            results['Assembly to Source Converter'] = {
                'success': False,
                'output': str(e),
                'output_dir': self.session_dir
            }
        
        # Final rapor oluştur
        self.generate_master_report(results)
        
        return results
    
    def generate_master_report(self, results):
        """Ana session raporu oluştur"""
        report_file = os.path.join(self.session_dir, 'EXTRACTION_REPORT.md')
        
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(f"# Master Extraction Report\\n\\n")
            f.write(f"**File**: {self.file_path}\\n")
            f.write(f"**Session**: {self.file_name}_{self.timestamp}\\n")
            f.write(f"**Date**: {time.strftime('%Y-%m-%d %H:%M:%S')}\\n\\n")
            
            # Extraction Results
            f.write("## Extraction Results\\n\\n")
            f.write("| Tool | Status | Output Directory |\\n")
            f.write("|------|--------|------------------|\\n")
            
            for tool_name, result in results.items():
                status = "✅ Success" if result['success'] else "❌ Failed"
                rel_path = os.path.relpath(result['output_dir'], self.session_dir)
                f.write(f"| {tool_name} | {status} | `{rel_path}/` |\\n")
            
            f.write("\\n## Directory Structure\\n\\n")
            f.write("```\\n")
            f.write(f"{self.file_name}_{self.timestamp}/\\n")
            
            for name, path in self.output_dirs.items():
                files_count = len([f for f in Path(path).rglob('*') if f.is_file()]) if os.path.exists(path) else 0
                f.write(f"├── {name}/ ({files_count} files)\\n")
            
            f.write("└── EXTRACTION_REPORT.md\\n")
            f.write("```\\n\\n")
            
            # Detailed Results
            f.write("## Detailed Results\\n\\n")
            
            for tool_name, result in results.items():
                f.write(f"### {tool_name}\\n\\n")
                f.write(f"**Status**: {('✅ Success' if result['success'] else '❌ Failed')}\\n")
                f.write(f"**Output Directory**: `{os.path.relpath(result['output_dir'], self.session_dir)}/`\\n\\n")
                
                if os.path.exists(result['output_dir']):
                    files = list(Path(result['output_dir']).rglob('*'))
                    files = [f for f in files if f.is_file()]
                    
                    if files:
                        f.write("**Generated Files:**\\n")
                        for file_path in files[:10]:  # İlk 10 dosya
                            rel_path = os.path.relpath(file_path, result['output_dir'])
                            file_size = file_path.stat().st_size
                            f.write(f"- `{rel_path}` ({file_size:,} bytes)\\n")
                        
                        if len(files) > 10:
                            f.write(f"- ... and {len(files) - 10} more files\\n")
                    else:
                        f.write("*No files generated*\\n")
                else:
                    f.write("*Output directory not found*\\n")
                
                f.write("\\n")
            
            # Summary Statistics
            successful_tools = sum(1 for r in results.values() if r['success'])
            total_files = sum(len([f for f in Path(path).rglob('*') if f.is_file()]) 
                            for path in self.output_dirs.values() if os.path.exists(path))
            
            f.write("## Summary\\n\\n")
            f.write(f"- **Tools Run**: {len(results)}\\n")
            f.write(f"- **Successful**: {successful_tools}\\n")
            f.write(f"- **Failed**: {len(results) - successful_tools}\\n")
            f.write(f"- **Total Files Generated**: {total_files}\\n")
            f.write(f"- **Session Directory Size**: {self.get_directory_size(self.session_dir):,} bytes\\n")
            
            # Quick Access
            f.write("\\n## Quick Access Commands\\n\\n")
            f.write("```bash\\n")
            f.write(f"# View all generated files\\n")
            f.write(f"find {self.session_dir} -type f | head -20\\n\\n")
            f.write(f"# View source code\\n")
            f.write(f"ls -la {self.output_dirs['source_code']}/\\n\\n")
            f.write(f"# View extracted resources\\n")
            f.write(f"ls -la {self.output_dirs['resources']}/\\n\\n")
            f.write(f"# View certificates\\n")
            f.write(f"ls -la {self.output_dirs['certificates']}/\\n")
            f.write("```\\n")
        
        print(f"📋 Master report: {report_file}")
        return report_file
    
    def get_directory_size(self, directory):
        """Dizin boyutunu hesapla"""
        try:
            total_size = 0
            for dirpath, dirnames, filenames in os.walk(directory):
                for filename in filenames:
                    filepath = os.path.join(dirpath, filename)
                    if os.path.exists(filepath):
                        total_size += os.path.getsize(filepath)
            return total_size
        except:
            return 0
    
    def create_launch_scripts(self):
        """Hızlı erişim scriptleri oluştur"""
        # View script
        view_script = os.path.join(self.session_dir, 'view_results.sh')
        with open(view_script, 'w') as f:
            f.write("#!/bin/bash\\n")
            f.write(f"# Quick view script for {self.file_name} extraction results\\n\\n")
            f.write(f"echo 'Extraction Results for {self.file_name}'\\n")
            f.write("echo '=================================='\\n\\n")
            
            for name, path in self.output_dirs.items():
                f.write(f"echo '{name.upper()}:'\\n")
                f.write(f"ls -la {path}/ 2>/dev/null || echo 'No files'\\n")
                f.write("echo\\n")
        
        os.chmod(view_script, 0o755)
        
        # Browse script
        browse_script = os.path.join(self.session_dir, 'browse_files.sh')
        with open(browse_script, 'w') as f:
            f.write("#!/bin/bash\\n")
            f.write(f"# File browser for {self.file_name} results\\n\\n")
            f.write(f"echo 'Opening file browser...'\\n")
            f.write(f"if command -v nautilus >/dev/null; then\\n")
            f.write(f"    nautilus {self.session_dir} &\\n")
            f.write(f"elif command -v dolphin >/dev/null; then\\n")
            f.write(f"    dolphin {self.session_dir} &\\n")
            f.write(f"elif command -v thunar >/dev/null; then\\n")
            f.write(f"    thunar {self.session_dir} &\\n")
            f.write(f"else\\n")
            f.write(f"    echo 'No file manager found. Directory: {self.session_dir}'\\n")
            f.write(f"fi\\n")
        
        os.chmod(browse_script, 0o755)
        
        return view_script, browse_script

def main():
    if len(sys.argv) < 2:
        print("Kullanım: python master_extractor.py <exe_dosyasi> [output_base]")
        print("\\nBu araç tüm extraction işlemlerini otomatik olarak yapar:")
        print("  🖥️  Source kod çıkarma")
        print("  🔐 Sertifika analizi")
        print("  💾 Memory dump analizi")
        print("  🔧 File reconstruction")
        print("  🎨 Resource extraction")
        sys.exit(1)
    
    file_path = sys.argv[1]
    output_base = sys.argv[2] if len(sys.argv) > 2 else "extracted"
    
    if not os.path.exists(file_path):
        print(f"❌ Dosya bulunamadı: {file_path}")
        sys.exit(1)
    
    extractor = MasterExtractor(file_path, output_base)
    
    print("⚠️  Bu işlem birkaç dakika sürebilir...")
    print()
    
    start_time = time.time()
    results = extractor.extract_all()
    end_time = time.time()
    
    # Launch scripts oluştur
    view_script, browse_script = extractor.create_launch_scripts()
    
    # Final özet
    successful = sum(1 for r in results.values() if r['success'])
    total = len(results)
    
    print("🎉 MASTER EXTRACTION COMPLETED!")
    print("=" * 50)
    print(f"⏱️  Duration: {end_time - start_time:.1f} seconds")
    print(f"✅ Success: {successful}/{total} tools")
    print(f"📂 Results: {extractor.session_dir}")
    print()
    print("🚀 Quick Actions:")
    print(f"   📋 View results: {view_script}")
    print(f"   📁 Browse files: {browse_script}")
    print(f"   📖 Read report: {extractor.session_dir}/EXTRACTION_REPORT.md")

if __name__ == "__main__":
    main()