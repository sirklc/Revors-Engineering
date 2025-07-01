#!/usr/bin/env python3
"""
Tool Testing Script
Tüm araçların çalışıp çalışmadığını test eder
"""

import os
import sys
import subprocess
import tempfile

def test_tool(tool_name, tool_script, test_file=None):
    """Bir aracı test et"""
    print(f"🔧 Testing {tool_name}...")
    
    if not os.path.exists(f"tools/{tool_script}"):
        print(f"   ❌ Script not found: tools/{tool_script}")
        return False
    
    # Test file yoksa geçici bir dosya oluştur
    if not test_file:
        with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as f:
            # Minimal PE header oluştur
            f.write(b'MZ' + b'\x00' * 58 + b'\x80\x00\x00\x00')  # DOS header
            f.write(b'\x00' * 120)  # Boş alan
            f.write(b'PE\x00\x00')  # PE signature
            f.write(b'\x00' * 100)  # Minimal PE header
            test_file = f.name
    
    # Test output directory
    test_output = tempfile.mkdtemp(prefix=f"test_{tool_name.lower().replace(' ', '_')}_")
    
    try:
        # Tool'u çalıştır
        cmd = ['python3', f'tools/{tool_script}', test_file, test_output]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            print(f"   ✅ {tool_name} working correctly")
            return True
        else:
            print(f"   ⚠️  {tool_name} returned error code {result.returncode}")
            if result.stderr:
                print(f"      Error: {result.stderr[:100]}...")
            return False
            
    except subprocess.TimeoutExpired:
        print(f"   ⏰ {tool_name} timeout")
        return False
    except Exception as e:
        print(f"   ❌ {tool_name} exception: {e}")
        return False
    finally:
        # Cleanup
        try:
            os.unlink(test_file)
            import shutil
            shutil.rmtree(test_output, ignore_errors=True)
        except:
            pass

def main():
    print("🧪 REVERSE ENGINEERING TOOLS TEST")
    print("=" * 50)
    
    tools_to_test = [
        ("Language Detector", "language_detector.py"),
        ("Advanced Decompiler", "advanced_decompiler.py"),
        ("PE Analyzer", "pe_analyzer.py"),
        ("Import Analyzer", "import_analyzer.py"),
        ("YARA Scanner", "yara_scanner.py"),
        ("String Extractor", "strings_extractor.py"),
        ("Disassembler", "disassembler.py"),
        ("Certificate Extractor", "certificate_extractor.py"),
        ("Memory Dump Analyzer", "memory_dump_analyzer.py"),
        ("File Reconstructor", "file_reconstructor.py"),
        ("Resource Extractor", "resource_extractor.py"),
        ("Master Extractor", "master_extractor.py"),
        ("Assembly to Source Converter", "asm_to_source_converter.py"),
        ("Report Generator", "report_generator.py")
    ]
    
    results = []
    
    for tool_name, tool_script in tools_to_test:
        success = test_tool(tool_name, tool_script)
        results.append((tool_name, success))
    
    print("\n📊 TEST RESULTS")
    print("=" * 30)
    
    successful = 0
    for tool_name, success in results:
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"   {tool_name:<25} {status}")
        if success:
            successful += 1
    
    print(f"\n🎯 Summary: {successful}/{len(results)} tools working")
    
    if successful == len(results):
        print("✅ All tools are working correctly!")
    else:
        print("⚠️  Some tools have issues. Check error messages above.")
    
    # Test dependencies
    print("\n🔍 Checking Dependencies...")
    dependencies = [
        ("Python 3", "python3 --version"),
        ("Capstone", "python3 -c 'import capstone; print(\"Capstone OK\")'"),
        ("Zenity (GUI)", "zenity --version"),
        ("File command", "file --version")
    ]
    
    for dep_name, cmd in dependencies:
        try:
            result = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                print(f"   ✅ {dep_name} available")
            else:
                print(f"   ❌ {dep_name} not available")
        except:
            print(f"   ❌ {dep_name} not available")

if __name__ == "__main__":
    main()