# 🔍 Advanced Reverse Engineering Toolkit

Bu proje Windows .exe dosyalarının kapsamlı reverse engineering analizi için gelişmiş araçlar ve workflow'lar içerir.

## 🚀 Özellikler

### 🔧 Core Analysis Tools
- **Language Detector**: Programming language detection (Python, C++, C#, Go, Java, Node.js)
- **Advanced Decompiler**: Source code reconstruction from assembly
- **Assembly to Source Converter**: .asm files to Python/C++/C# conversion
- **PE Analyzer**: Detaylı PE header, section ve entropy analizi
- **Import/Export Analyzer**: DLL ve fonksiyon bağımlılıkları
- **String Extractor**: ASCII/Unicode string çıkarma
- **YARA Scanner**: Malware detection rules
- **Packer Detector**: UPX, ASPack vs. detection

### 📊 Reporting
- **HTML Reports**: Görsel ve detaylı analiz raporları
- **JSON Export**: Programatik erişim için structured data
- **Real-time Analysis**: Otomatik analiz pipeline

### 🌐 Interfaces
- **Command Line**: Hızlı analiz için CLI tools
- **Web Interface**: Flask tabanlı web arayüzü
- **REST API**: Entegrasyon için API endpoints

## 📁 Dizin Yapısı

```
├── tools/                  # Core analysis tools
│   ├── pe_analyzer.py      # PE format analysis
│   ├── import_analyzer.py  # Import/Export tables
│   ├── strings_extractor.py # String extraction
│   ├── yara_scanner.py     # YARA rules engine
│   └── report_generator.py # Report generation
├── scripts/                # Automation scripts
│   └── analyze_exe.sh      # Full analysis pipeline
├── rules/                  # YARA rules (auto-generated)
├── samples/                # Test samples directory
├── output/                 # Analysis results
├── reports/                # Generated reports
├── templates/              # Web interface templates
├── web_interface.py        # Flask web server
└── requirements.txt        # Python dependencies
```

## 🛠️ Kurulum

```bash
# Python bağımlılıklarını yükle
pip install -r requirements.txt

# Execution permissions
chmod +x scripts/analyze_exe.sh
```

## 📋 Kullanım

### 🖱️ Interactive GUI (Önerilen)

```bash
# Kullanıcı dostu interface
python3 re_analyzer.py

# Veya desktop launcher'ı çift tıklayın:
./reverse_engineering_analyzer.desktop
```

**Özellikler:**
- 🖱️ Drag & Drop dosya desteği
- 📁 GUI file browser (Zenity/KDialog)
- 🎯 Analiz seçenekleri menüsü
- 📊 Real-time progress gösterimi
- 📋 Sonuç özetleri ve hızlı erişim

### 🚀 Command Line Interface

```bash
# Tam analiz (11 araç)
./scripts/analyze_exe.sh sample.exe

# Master extractor (tek komut)
python3 tools/master_extractor.py sample.exe

# Bireysel araçlar
python3 tools/language_detector.py sample.exe      # Programming language detection
python3 tools/advanced_decompiler.py sample.exe    # Original source code reconstruction  
python3 tools/disassembler.py sample.exe           # Assembly + automatic source conversion
python3 tools/asm_to_source_converter.py file.asm  # Convert .asm to Python/C++/C#
python3 tools/certificate_extractor.py sample.exe  # Sertifika analizi
python3 tools/resource_extractor.py sample.exe     # Resource çıkarma
python3 tools/memory_dump_analyzer.py sample.exe   # Memory dump analizi

# Test ve debug
python3 test_tools.py  # Tüm araçları test et
```

### 🌐 Web Interface

```bash
# Web sunucusu başlat
python3 web_interface.py

# Tarayıcıda aç: http://localhost:5000
```

### 📡 REST API

```bash
# Dosya analizi
curl -X POST -F "file=@sample.exe" http://localhost:5000/api/analyze
```

## 🔍 Analiz Özellikleri

### PE Analysis
- ✅ DOS/PE header validation
- ✅ Section analysis (entropy, characteristics)
- ✅ Architecture detection (x86/x64/ARM)
- ✅ Timestamp analysis
- ✅ Anomaly detection

### Import/Export Analysis
- ✅ DLL dependencies
- ✅ Function imports
- ✅ Suspicious API detection
- ✅ Ordinal vs named imports

### Security Analysis
- ✅ Packer detection (UPX, ASPack, etc.)
- ✅ Entropy analysis
- ✅ YARA rules matching
- ✅ Suspicious string patterns

### Reporting
- ✅ HTML reports with charts
- ✅ JSON structured data
- ✅ Executive summaries
- ✅ IOC extraction

## 🎯 YARA Rules

Otomatik oluşturulan kurallar:
- `upx_detection.yar` - UPX packer detection
- `suspicious_apis.yar` - Malicious API calls
- `crypto_detection.yar` - Cryptographic functions
- `pe_anomaly.yar` - PE structure anomalies

## 🔒 Güvenlik Uyarıları

⚠️ **ÖNEMLİ GÜVENLİK UYARILARI**

1. **İzole Ortam**: Şüpheli dosyaları sadece VM'de çalıştırın
2. **Network Isolation**: Analiz sırasında internet bağlantısını kesin
3. **Sandbox**: Malware analysis için dedicated sandbox kullanın
4. **Backup**: Sistem snapshot'ı alın
5. **Legal**: Bu araçlar sadece güvenlik araştırması için kullanılmalıdır
6. **İllegal**: Bu araçlar farklı bir durumda kullanıldığı taktirde hiçbir şekilde sorumluluk kabul edilmemektedir.

## 📖 Örnek Workflow

```bash
# 1. Temel analiz
./scripts/analyze_exe.sh suspicious.exe

# 2. Sonuçları incele
ls -la output/suspicious_analysis_*/

# 3. HTML raporunu aç
open output/suspicious_analysis_*/suspicious_report_*.html

# 4. JSON data'yı işle
python3 -c "
import json
with open('output/suspicious_analysis_*/suspicious_report_*.json') as f:
    data = json.load(f)
    print(f'Entropy: {data[\"pe_info\"][\"overall_entropy\"]:.2f}')
"
```

## 🤝 Katkıda Bulunma

1. Fork the repository
2. Create feature branch
3. Add tests for new features
4. Submit pull request

## 📄 Lisans

Bu proje eğitim ve güvenlik araştırması amacıyla geliştirilmiştir. Kötü amaçlı kullanım kesinlikle yasaktır.

## 🔗 Ek Kaynaklar

- [PE Format Documentation](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format)
- [YARA Documentation](https://yara.readthedocs.io/)
- [Malware Analysis Techniques](https://github.com/rshipp/awesome-malware-analysis)
