#!/usr/bin/env python3
"""
Interactive Reverse Engineering Analyzer
Drag & Drop destekli kullanıcı dostu terminal interface
"""

import os
import sys
import time
import subprocess
import tempfile
from pathlib import Path

class InteractiveREAnalyzer:
    def __init__(self):
        self.tools_dir = "tools"
        self.output_base = "extracted"
        self.clear_screen()
        
    def clear_screen(self):
        """Ekranı temizle"""
        os.system('clear' if os.name == 'posix' else 'cls')
    
    def print_banner(self):
        """Ana banner'ı göster"""
        banner = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                    🔍 REVERSE ENGINEERING ANALYZER 🔍                        ║
║                         Advanced Malware Analysis Tool                       ║
║                              v2.0 - Enhanced                                ║
╚══════════════════════════════════════════════════════════════════════════════╝

🎯 ÖZELLIKLER:
  🖥️  Source Code Extraction (Python, C++, C# reconstruction)
  🔄 Assembly to Source Code Conversion
  🔐 Digital Certificate Analysis  
  💾 Memory Dump Analysis
  🔧 File Structure Reconstruction
  🎨 Resource Extraction (Icons, Strings, etc.)
  📊 Comprehensive HTML/JSON Reports

⚠️  GÜVENLİK UYARISI: Sadece güvenlik araştırması için kullanın!
"""
        print(banner)
    
    def show_menu(self):
        """Ana menüyü göster"""
        menu = """
┌─────────────────────────────────────────────────────────┐
│                     ANALYSIS OPTIONS                    │
├─────────────────────────────────────────────────────────┤
│  1️⃣  📁 File Browser (Select .exe file)                 │
│  2️⃣  📋 Drag & Drop (Paste file path)                   │  
│  3️⃣  🔧 Advanced Options                                │
│  4️⃣  📊 View Previous Results                           │
│  5️⃣  ❓ Help & Documentation                           │
│  6️⃣  🚪 Exit                                           │
└─────────────────────────────────────────────────────────┘
"""
        print(menu)
    
    def get_file_via_browser(self):
        """File browser ile dosya seç"""
        print("🔍 File Browser Mode")
        print("─" * 50)
        
        # Zenity veya dialog ile file picker
        try:
            if self.check_command("zenity"):
                result = subprocess.run([
                    "zenity", "--file-selection", 
                    "--title=Select .exe file for analysis",
                    "--file-filter=Executable files (*.exe) | *.exe",
                    "--file-filter=All files (*) | *"
                ], capture_output=True, text=True)
                
                if result.returncode == 0:
                    return result.stdout.strip()
            
            elif self.check_command("kdialog"):
                result = subprocess.run([
                    "kdialog", "--getopenfilename", ".", "*.exe|Executable files"
                ], capture_output=True, text=True)
                
                if result.returncode == 0:
                    return result.stdout.strip()
            
            else:
                print("❌ GUI file picker bulunamadı")
                return self.get_file_manual()
                
        except Exception as e:
            print(f"❌ File picker hatası: {e}")
            return self.get_file_manual()
        
        return None
    
    def get_file_manual(self):
        """Manuel dosya path girişi"""
        print("\\n📋 Manual File Path Entry")
        print("─" * 30)
        print("💡 Tip: Dosyayı terminale sürükleyip bırakabilirsiniz")
        print("💡 Tip: Tab tuşu ile auto-complete kullanın")
        print()
        
        while True:
            try:
                path = input("📁 File path (veya 'q' çıkış için): ").strip()
                
                if path.lower() in ['q', 'quit', 'exit']:
                    return None
                
                # Tırnak işaretlerini temizle
                path = path.strip('\'"')
                
                if not path:
                    continue
                
                # Path expansion
                path = os.path.expanduser(path)
                path = os.path.abspath(path)
                
                if not os.path.exists(path):
                    print(f"❌ Dosya bulunamadı: {path}")
                    continue
                
                if not os.path.isfile(path):
                    print(f"❌ Bu bir dosya değil: {path}")
                    continue
                
                # File size check
                file_size = os.path.getsize(path)
                if file_size > 500 * 1024 * 1024:  # 500MB limit
                    response = input(f"⚠️  Dosya çok büyük ({file_size // (1024*1024)}MB). Devam? (y/N): ")
                    if response.lower() != 'y':
                        continue
                
                return path
                
            except KeyboardInterrupt:
                print("\\n❌ İptal edildi")
                return None
            except Exception as e:
                print(f"❌ Hata: {e}")
    
    def check_command(self, command):
        """Komutun varlığını kontrol et"""
        try:
            subprocess.run(["which", command], capture_output=True, check=True)
            return True
        except:
            return False
    
    def show_analysis_options(self, file_path):
        """Analiz seçeneklerini göster"""
        file_name = os.path.basename(file_path)
        file_size = os.path.getsize(file_path)
        
        print(f"\\n📄 Selected File: {file_name}")
        print(f"📏 Size: {file_size:,} bytes ({file_size / (1024*1024):.1f} MB)")
        print("─" * 80)
        
        options = """
┌─────────────────────────────────────────────────────────┐
│                   ANALYSIS OPTIONS                      │
├─────────────────────────────────────────────────────────┤
│  1️⃣  🚀 Full Analysis (Recommended)                     │
│  2️⃣  🖥️  Source Code Only                               │
│  3️⃣  🔐 Certificates Only                               │
│  4️⃣  🎨 Resources Only                                  │
│  5️⃣  💾 Memory Dump Only                               │
│  6️⃣  🔧 Custom Analysis                                 │
│  7️⃣  🔙 Back to Main Menu                              │
└─────────────────────────────────────────────────────────┘
"""
        print(options)
        
        while True:
            try:
                choice = input("\\n🎯 Seçim yapın (1-7): ").strip()
                
                if choice == '1':
                    return self.run_full_analysis(file_path)
                elif choice == '2':
                    return self.run_single_tool("disassembler.py", file_path, "source_code")
                elif choice == '3':
                    return self.run_single_tool("certificate_extractor.py", file_path, "certificates")
                elif choice == '4':
                    return self.run_single_tool("resource_extractor.py", file_path, "resources")
                elif choice == '5':
                    return self.run_single_tool("memory_dump_analyzer.py", file_path, "dumps")
                elif choice == '6':
                    return self.run_custom_analysis(file_path)
                elif choice == '7':
                    return False
                else:
                    print("❌ Geçersiz seçim. 1-7 arası bir sayı girin.")
                    
            except KeyboardInterrupt:
                print("\\n❌ İptal edildi")
                return False
    
    def run_full_analysis(self, file_path):
        """Tam analiz çalıştır"""
        print("\\n🚀 FULL ANALYSIS BAŞLATILIYOR...")
        print("=" * 80)
        
        # Estimated time
        file_size_mb = os.path.getsize(file_path) / (1024 * 1024)
        estimated_time = max(30, int(file_size_mb * 2))  # 2 saniye per MB
        
        print(f"⏱️  Tahmini süre: ~{estimated_time} saniye")
        print("💡 İşlem sırasında terminal kapatmayın!")
        print()
        
        confirm = input("🤔 Devam etmek istiyor musunuz? (Y/n): ").strip().lower()
        if confirm == 'n':
            return False
        
        # Master extractor çalıştır
        start_time = time.time()
        success = self.run_master_extractor(file_path)
        end_time = time.time()
        
        duration = int(end_time - start_time)
        
        if success:
            print(f"\\n🎉 ANALYSIS COMPLETED! ({duration}s)")
            self.show_results_summary(file_path)
        else:
            print(f"\\n❌ Analysis failed after {duration}s")
        
        input("\\n📱 Press Enter to continue...")
        return True
    
    def run_single_tool(self, tool_script, file_path, output_subdir):
        """Tek araç çalıştır"""
        tool_name = tool_script.replace('.py', '').replace('_', ' ').title()
        print(f"\\n🔧 {tool_name} Analysis")
        print("─" * 50)
        
        file_base = os.path.splitext(os.path.basename(file_path))[0]
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        output_dir = os.path.join(self.output_base, f"{file_base}_{timestamp}", output_subdir)
        
        os.makedirs(output_dir, exist_ok=True)
        
        cmd = ['python3', os.path.join(self.tools_dir, tool_script), file_path, output_dir]
        
        print(f"🔄 Running: {tool_name}")
        print(f"📂 Output: {output_dir}")
        print()
        
        try:
            result = subprocess.run(cmd, capture_output=False, text=True, timeout=300)
            
            if result.returncode == 0:
                print(f"\\n✅ {tool_name} completed successfully!")
                print(f"📂 Results saved to: {output_dir}")
            else:
                print(f"\\n❌ {tool_name} failed with exit code {result.returncode}")
                
        except subprocess.TimeoutExpired:
            print(f"\\n⏰ {tool_name} timeout (5 minutes)")
        except Exception as e:
            print(f"\\n💥 {tool_name} error: {e}")
        
        input("\\n📱 Press Enter to continue...")
        return True
    
    def run_master_extractor(self, file_path):
        """Master extractor çalıştır"""
        cmd = ['python3', os.path.join(self.tools_dir, 'master_extractor.py'), file_path, self.output_base]
        
        try:
            # Real-time output ile çalıştır
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, 
                                     universal_newlines=True, bufsize=1)
            
            for line in process.stdout:
                print(line.rstrip())
            
            process.wait()
            return process.returncode == 0
            
        except Exception as e:
            print(f"❌ Master extractor hatası: {e}")
            return False
    
    def show_results_summary(self, file_path):
        """Sonuçları özetle"""
        file_base = os.path.splitext(os.path.basename(file_path))[0]
        
        # En son session'ı bul
        extracted_path = Path(self.output_base)
        if not extracted_path.exists():
            return
            
        session_dirs = [d for d in extracted_path.iterdir() 
                       if d.is_dir() and d.name.startswith(file_base)]
        
        if not session_dirs:
            return
            
        # En son olanı al
        latest_session = max(session_dirs, key=lambda x: x.stat().st_mtime)
        
        print("\\n📊 ANALYSIS SUMMARY")
        print("=" * 50)
        print(f"📂 Session: {latest_session.name}")
        
        # Alt dizinleri kontrol et
        subdirs = {
            'source_code': '🖥️  Source Code',
            'certificates': '🔐 Certificates', 
            'resources': '🎨 Resources',
            'dumps': '💾 Memory Dumps',
            'reconstructed': '🔧 Reconstructed'
        }
        
        for subdir, label in subdirs.items():
            subdir_path = latest_session / subdir
            if subdir_path.exists():
                file_count = len([f for f in subdir_path.rglob('*') if f.is_file()])
                print(f"   {label}: {file_count} files")
        
        # Quick actions
        print("\\n🚀 QUICK ACTIONS:")
        print(f"   📁 Open folder: nautilus '{latest_session}' &")
        print(f"   📋 List files: ls -la '{latest_session}'")
        
        # HTML report check
        html_files = list(latest_session.rglob('*.html'))
        if html_files:
            print(f"   🌐 View report: firefox '{html_files[0]}' &")
    
    def run_custom_analysis(self, file_path):
        """Özel analiz seçenekleri"""
        print("\\n🔧 CUSTOM ANALYSIS")
        print("─" * 30)
        
        tools = {
            '1': ('PE Analyzer', 'pe_analyzer.py'),
            '2': ('Import Analyzer', 'import_analyzer.py'),
            '3': ('YARA Scanner', 'yara_scanner.py'),
            '4': ('String Extractor', 'strings_extractor.py'),
            '5': ('Disassembler', 'disassembler.py'),
            '6': ('Certificate Extractor', 'certificate_extractor.py'),
            '7': ('Memory Dump Analyzer', 'memory_dump_analyzer.py'),
            '8': ('File Reconstructor', 'file_reconstructor.py'),
            '9': ('Resource Extractor', 'resource_extractor.py')
        }
        
        print("Available Tools:")
        for key, (name, _) in tools.items():
            print(f"  {key}️⃣  {name}")
        
        print("  0️⃣  Back to menu")
        
        while True:
            try:
                choice = input("\\n🎯 Select tool (0-9): ").strip()
                
                if choice == '0':
                    return False
                
                if choice in tools:
                    tool_name, tool_script = tools[choice]
                    output_subdir = tool_script.replace('.py', '').replace('_', '')
                    return self.run_single_tool(tool_script, file_path, output_subdir)
                else:
                    print("❌ Invalid choice. Enter 0-9.")
                    
            except KeyboardInterrupt:
                print("\\n❌ Cancelled")
                return False
    
    def view_previous_results(self):
        """Önceki sonuçları göster"""
        print("\\n📊 PREVIOUS RESULTS")
        print("─" * 30)
        
        extracted_path = Path(self.output_base)
        if not extracted_path.exists():
            print("❌ No previous results found")
            input("\\n📱 Press Enter to continue...")
            return
        
        session_dirs = [d for d in extracted_path.iterdir() if d.is_dir()]
        session_dirs.sort(key=lambda x: x.stat().st_mtime, reverse=True)
        
        if not session_dirs:
            print("❌ No previous results found")
            input("\\n📱 Press Enter to continue...")
            return
        
        print(f"Found {len(session_dirs)} previous sessions:\\n")
        
        for i, session_dir in enumerate(session_dirs[:10], 1):
            mtime = session_dir.stat().st_mtime
            time_str = time.strftime("%Y-%m-%d %H:%M", time.localtime(mtime))
            file_count = len([f for f in session_dir.rglob('*') if f.is_file()])
            
            print(f"  {i:2d}. {session_dir.name}")
            print(f"      📅 {time_str} | 📄 {file_count} files")
        
        if len(session_dirs) > 10:
            print(f"\\n... and {len(session_dirs) - 10} more sessions")
        
        print("\\n🚀 Quick Commands:")
        print(f"   📁 Open latest: nautilus '{session_dirs[0]}' &")
        print(f"   📋 List latest: ls -la '{session_dirs[0]}'")
        
        input("\\n📱 Press Enter to continue...")
    
    def show_help(self):
        """Yardım ve dokümantasyon"""
        help_text = """
📚 HELP & DOCUMENTATION
═══════════════════════

🎯 GENEL KULLANIM:
  • .exe, .dll, .bin dosyalarını analiz edebilirsiniz
  • Drag & drop için dosyayı terminale sürükleyin
  • Ctrl+C ile işlemi iptal edebilirsiniz

🔧 ANALYSIS TOOLS:
  🖥️  Disassembler: Assembly kod + C pseudocode
  🔐 Certificate: Digital signature analizi
  💾 Memory Dump: Embedded PE detection
  🎨 Resources: Icon, string, manifest çıkarma
  🔧 Reconstructor: Proje yapısı oluşturma

📊 OUTPUT FORMATS:
  • Assembly files (.asm)
  • C pseudocode (.c)  
  • HTML reports (.html)
  • JSON data (.json)
  • Raw binary (.bin)

⚠️  GÜVENLİK:
  • Sadece güvenlik araştırması için kullanın
  • Şüpheli dosyaları VM'de çalıştırın
  • Network'ü izole edin

🔗 USEFUL COMMANDS:
  • ls extracted/                    # Tüm sonuçları listele
  • firefox extracted/*/report.html  # HTML raporu aç
  • nautilus extracted/              # File manager'da aç

📧 SUPPORT:
  GitHub: https://github.com/user/reverse-engineering-toolkit
  Issues: Report bugs and feature requests
"""
        
        self.clear_screen()
        print(help_text)
        input("\\n📱 Press Enter to return to main menu...")
    
    def run(self):
        """Ana program döngüsü"""
        while True:
            self.clear_screen()
            self.print_banner()
            self.show_menu()
            
            try:
                choice = input("\\n🎯 Seçim yapın (1-6): ").strip()
                
                if choice == '1':
                    file_path = self.get_file_via_browser()
                    if file_path:
                        self.show_analysis_options(file_path)
                
                elif choice == '2':
                    file_path = self.get_file_manual()
                    if file_path:
                        self.show_analysis_options(file_path)
                
                elif choice == '3':
                    print("\\n🔧 Advanced Options coming soon...")
                    input("📱 Press Enter to continue...")
                
                elif choice == '4':
                    self.view_previous_results()
                
                elif choice == '5':
                    self.show_help()
                
                elif choice == '6':
                    print("\\n👋 Exiting Reverse Engineering Analyzer...")
                    print("🔒 Remember: Use responsibly for security research only!")
                    sys.exit(0)
                
                else:
                    print("❌ Geçersiz seçim. 1-6 arası bir sayı girin.")
                    time.sleep(1)
                    
            except KeyboardInterrupt:
                print("\\n\\n👋 Exiting...")
                sys.exit(0)
            except Exception as e:
                print(f"\\n❌ Unexpected error: {e}")
                time.sleep(2)

def main():
    # Check if we're in the right directory
    if not os.path.exists("tools"):
        print("❌ Error: 'tools' directory not found!")
        print("💡 Please run this script from the project root directory")
        sys.exit(1)
    
    analyzer = InteractiveREAnalyzer()
    analyzer.run()

if __name__ == "__main__":
    main()