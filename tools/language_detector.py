#!/usr/bin/env python3
"""
Programming Language Detector
PE dosyalarının hangi dilde yazıldığını tespit eder
"""

import os
import sys
import struct
import re
from collections import defaultdict, Counter

class LanguageDetector:
    def __init__(self, file_path):
        self.file_path = file_path
        self.file_data = None
        self.strings = []
        self.imports = []
        self.detected_languages = []
        self.confidence_scores = {}
        
    def load_file(self):
        """Dosyayı yükle"""
        try:
            with open(self.file_path, 'rb') as f:
                self.file_data = f.read()
            return True
        except Exception as e:
            print(f"Dosya yüklenemedi: {e}")
            return False
    
    def extract_strings(self):
        """Stringleri çıkar"""
        # ASCII strings
        ascii_pattern = rb'[!-~]{4,}'
        ascii_matches = re.findall(ascii_pattern, self.file_data)
        ascii_strings = [match.decode('ascii', errors='ignore') for match in ascii_matches]
        
        # Unicode strings  
        unicode_strings = []
        i = 0
        current_string = ""
        while i < len(self.file_data) - 1:
            if self.file_data[i] != 0 and self.file_data[i+1] == 0:
                current_string += chr(self.file_data[i])
            elif self.file_data[i] == 0 and self.file_data[i+1] == 0:
                if len(current_string) >= 4:
                    unicode_strings.append(current_string)
                current_string = ""
            else:
                if current_string and len(current_string) >= 4:
                    unicode_strings.append(current_string)
                current_string = ""
            i += 2
        
        self.strings = ascii_strings + unicode_strings
        return self.strings
    
    def detect_python(self):
        """Python executable tespiti"""
        confidence = 0
        indicators = []
        
        # Python runtime signatures
        python_patterns = [
            r'python\d*\.dll',
            r'PyObject',
            r'PyDict_',
            r'PyList_',
            r'PyTuple_',
            r'__pycache__',
            r'\.pyc',
            r'\.pyo',
            r'site-packages',
            r'pip',
            r'setuptools',
            r'distutils',
            r'PYTHONPATH',
            r'sys\.executable',
            r'__name__.*__main__',
            r'import\s+\w+',
            r'from\s+\w+\s+import',
            r'def\s+\w+\(',
            r'class\s+\w+',
            r'if\s+__name__\s*==\s*[\'"]__main__[\'"]'
        ]
        
        for pattern in python_patterns:
            matches = []
            for string in self.strings:
                if re.search(pattern, string, re.IGNORECASE):
                    matches.append(string)
            
            if matches:
                if 'python' in pattern.lower():
                    confidence += 30
                    indicators.append(f"Python runtime: {matches[0]}")
                elif 'py' in pattern.lower():
                    confidence += 20
                    indicators.append(f"Python files: {len(matches)} matches")
                elif pattern in ['def ', 'class ', 'import ']:
                    confidence += 15
                    indicators.append(f"Python syntax: {pattern}")
                else:
                    confidence += 10
                    indicators.append(f"Python indicator: {pattern}")
        
        # PyInstaller specific
        pyinstaller_patterns = [
            'pyi-runtime-tmpdir',
            'PyInstaller',
            '_MEIPASS',
            'bootloader',
            'pyi_rth_'
        ]
        
        for pattern in pyinstaller_patterns:
            if any(pattern in s for s in self.strings):
                confidence += 40
                indicators.append(f"PyInstaller: {pattern}")
        
        # Py2exe specific
        py2exe_patterns = ['py2exe', 'python27.dll', 'python36.dll', 'python37.dll', 'python38.dll', 'python39.dll']
        for pattern in py2exe_patterns:
            if any(pattern in s.lower() for s in self.strings):
                confidence += 35
                indicators.append(f"Py2exe: {pattern}")
        
        return min(confidence, 100), indicators
    
    def detect_dotnet(self):
        """Microsoft .NET tespiti"""
        confidence = 0
        indicators = []
        
        # .NET runtime signatures
        dotnet_patterns = [
            r'mscoree\.dll',
            r'mscorlib',
            r'System\.',
            r'Microsoft\.',
            r'\.NET Framework',
            r'CLR',
            r'Assembly',
            r'namespace\s+\w+',
            r'using\s+System',
            r'public\s+class',
            r'\.exe\.config',
            r'app\.config'
        ]
        
        for pattern in dotnet_patterns:
            matches = []
            for string in self.strings:
                if re.search(pattern, string, re.IGNORECASE):
                    matches.append(string)
            
            if matches:
                if 'mscoree' in pattern or 'mscorlib' in pattern:
                    confidence += 40
                    indicators.append(f".NET runtime: {matches[0]}")
                elif 'System.' in pattern or 'Microsoft.' in pattern:
                    confidence += 25
                    indicators.append(f".NET framework: {len(matches)} matches")
                else:
                    confidence += 15
                    indicators.append(f".NET indicator: {pattern}")
        
        # Check for .NET header
        try:
            if b'.NET Framework' in self.file_data or b'mscoree.dll' in self.file_data:
                confidence += 50
                indicators.append(".NET header found")
        except:
            pass
        
        return min(confidence, 100), indicators
    
    def detect_cpp(self):
        """C/C++ executable tespiti"""
        confidence = 0
        indicators = []
        
        # C++ runtime signatures
        cpp_patterns = [
            r'msvcrt\.dll',
            r'msvcr\d+\.dll',
            r'vcruntime\d+\.dll',
            r'std::\w+',
            r'__cdecl',
            r'__stdcall',
            r'__fastcall',
            r'#include\s*<',
            r'iostream',
            r'vector',
            r'string',
            r'malloc',
            r'free',
            r'printf',
            r'scanf'
        ]
        
        for pattern in cpp_patterns:
            matches = []
            for string in self.strings:
                if re.search(pattern, string, re.IGNORECASE):
                    matches.append(string)
            
            if matches:
                if 'msvcr' in pattern or 'vcruntime' in pattern:
                    confidence += 35
                    indicators.append(f"C++ runtime: {matches[0]}")
                elif 'std::' in pattern:
                    confidence += 30
                    indicators.append(f"C++ STL: {len(matches)} matches")
                elif '__' in pattern:
                    confidence += 20
                    indicators.append(f"C++ calling convention: {pattern}")
                else:
                    confidence += 10
                    indicators.append(f"C++ indicator: {pattern}")
        
        return min(confidence, 100), indicators
    
    def detect_go(self):
        """Go executable tespiti"""
        confidence = 0
        indicators = []
        
        go_patterns = [
            r'go\.build',
            r'runtime\.main',
            r'sync\.',
            r'fmt\.',
            r'os\.',
            r'net/http',
            r'encoding/json',
            r'Go build ID',
            r'runtime\.goexit',
            r'sync\.mutex',
            r'chan\s+',
            r'goroutine',
            r'GOROOT',
            r'GOPATH'
        ]
        
        for pattern in go_patterns:
            matches = []
            for string in self.strings:
                if re.search(pattern, string, re.IGNORECASE):
                    matches.append(string)
            
            if matches:
                if 'go.build' in pattern or 'Go build' in pattern:
                    confidence += 40
                    indicators.append(f"Go build info: {matches[0]}")
                elif 'runtime.' in pattern:
                    confidence += 25
                    indicators.append(f"Go runtime: {pattern}")
                else:
                    confidence += 15
                    indicators.append(f"Go indicator: {pattern}")
        
        return min(confidence, 100), indicators
    
    def detect_rust(self):
        """Rust executable tespiti"""
        confidence = 0
        indicators = []
        
        rust_patterns = [
            r'rustc',
            r'cargo',
            r'std::',
            r'core::',
            r'alloc::',
            r'Result<',
            r'Option<',
            r'Vec<',
            r'HashMap',
            r'thread::spawn',
            r'panic!',
            r'\.rs',
            r'rust_eh_personality'
        ]
        
        for pattern in rust_patterns:
            matches = []
            for string in self.strings:
                if re.search(pattern, string, re.IGNORECASE):
                    matches.append(string)
            
            if matches:
                if 'rustc' in pattern or 'cargo' in pattern:
                    confidence += 35
                    indicators.append(f"Rust toolchain: {matches[0]}")
                elif 'rust_eh' in pattern:
                    confidence += 30
                    indicators.append("Rust exception handling")
                else:
                    confidence += 15
                    indicators.append(f"Rust indicator: {pattern}")
        
        return min(confidence, 100), indicators
    
    def detect_nodejs(self):
        """Node.js executable tespiti"""
        confidence = 0
        indicators = []
        
        nodejs_patterns = [
            r'node\.exe',
            r'v8::', 
            r'process\.env',
            r'require\(',
            r'module\.exports',
            r'package\.json',
            r'npm',
            r'electron',
            r'nw\.js',
            r'nexe',
            r'pkg'
        ]
        
        for pattern in nodejs_patterns:
            matches = []
            for string in self.strings:
                if re.search(pattern, string, re.IGNORECASE):
                    matches.append(string)
            
            if matches:
                if 'node.exe' in pattern or 'electron' in pattern:
                    confidence += 35
                    indicators.append(f"Node.js runtime: {matches[0]}")
                elif 'v8::' in pattern:
                    confidence += 25
                    indicators.append("V8 JavaScript engine")
                else:
                    confidence += 15
                    indicators.append(f"Node.js indicator: {pattern}")
        
        return min(confidence, 100), indicators
    
    def detect_java(self):
        """Java executable tespiti"""
        confidence = 0
        indicators = []
        
        java_patterns = [
            r'java\.exe',
            r'jvm\.dll',
            r'java\.',
            r'javax\.',
            r'sun\.',
            r'oracle\.',
            r'\.class',
            r'\.jar',
            r'META-INF',
            r'launch4j',
            r'JavaLaunchHelper'
        ]
        
        for pattern in java_patterns:
            matches = []
            for string in self.strings:
                if re.search(pattern, string, re.IGNORECASE):
                    matches.append(string)
            
            if matches:
                if 'java.exe' in pattern or 'jvm.dll' in pattern:
                    confidence += 35
                    indicators.append(f"Java runtime: {matches[0]}")
                elif 'launch4j' in pattern:
                    confidence += 30
                    indicators.append("Launch4j wrapper")
                else:
                    confidence += 15
                    indicators.append(f"Java indicator: {pattern}")
        
        return min(confidence, 100), indicators
    
    def analyze(self):
        """Ana analiz fonksiyonu"""
        if not self.load_file():
            return None
        
        print(f"🔍 LANGUAGE DETECTION: {os.path.basename(self.file_path)}")
        print("=" * 80)
        
        # String extraction
        self.extract_strings()
        print(f"📝 Extracted {len(self.strings)} strings for analysis")
        
        # Language detection
        detectors = {
            'Python': self.detect_python,
            '.NET/C#': self.detect_dotnet,
            'C/C++': self.detect_cpp,
            'Go': self.detect_go,
            'Rust': self.detect_rust,
            'Node.js': self.detect_nodejs,
            'Java': self.detect_java
        }
        
        results = {}
        print(f"\n🎯 LANGUAGE DETECTION RESULTS:")
        print("-" * 50)
        
        for lang_name, detector_func in detectors.items():
            try:
                confidence, indicators = detector_func()
                results[lang_name] = {
                    'confidence': confidence,
                    'indicators': indicators
                }
                
                if confidence > 0:
                    print(f"{lang_name:<12} {confidence:3d}% confidence")
                    for indicator in indicators[:3]:  # İlk 3 indicator
                        print(f"             └─ {indicator}")
                else:
                    print(f"{lang_name:<12}   0% confidence")
                    
            except Exception as e:
                print(f"{lang_name:<12} ERROR: {e}")
                results[lang_name] = {'confidence': 0, 'indicators': []}
        
        # En yüksek confidence'ı bul
        best_match = max(results.items(), key=lambda x: x[1]['confidence'])
        
        print(f"\n🏆 MOST LIKELY LANGUAGE:")
        if best_match[1]['confidence'] > 30:
            print(f"   {best_match[0]} ({best_match[1]['confidence']}% confidence)")
            self.detected_languages = [best_match[0]]
        else:
            print(f"   Unknown/Undetected (highest: {best_match[0]} {best_match[1]['confidence']}%)")
            self.detected_languages = ['Unknown']
        
        # Multiple possibilities
        high_confidence = [(lang, data) for lang, data in results.items() if data['confidence'] > 30]
        if len(high_confidence) > 1:
            print(f"\n🤔 MULTIPLE POSSIBILITIES:")
            for lang, data in high_confidence:
                print(f"   {lang}: {data['confidence']}%")
        
        return {
            'primary_language': best_match[0] if best_match[1]['confidence'] > 30 else 'Unknown',
            'confidence': best_match[1]['confidence'],
            'all_results': results,
            'indicators': best_match[1]['indicators']
        }

def main():
    if len(sys.argv) != 2:
        print("Kullanım: python language_detector.py <exe_dosyasi>")
        sys.exit(1)
    
    file_path = sys.argv[1]
    if not os.path.exists(file_path):
        print(f"Dosya bulunamadı: {file_path}")
        sys.exit(1)
    
    detector = LanguageDetector(file_path)
    result = detector.analyze()
    
    if result:
        print(f"\n✅ Detection completed!")
        print(f"📄 Primary Language: {result['primary_language']}")
        print(f"🎯 Confidence: {result['confidence']}%")

if __name__ == "__main__":
    main()