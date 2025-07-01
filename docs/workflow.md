# .exe Dosyası Analiz Workflow'u

## Hızlı Başlangıç

```bash
# Tam analiz için
./scripts/analyze_exe.sh sample.exe

# Sadece PE analizi
python3 tools/pe_analyzer.py sample.exe

# Sadece string çıkarma
python3 tools/strings_extractor.py sample.exe
```

## Detaylı Analiz Adımları

### 1. İlk İnceleme
- Dosya boyutu ve hash değerleri
- PE header kontrolü
- Temel dosya bilgileri

### 2. String Analizi
- ASCII ve Unicode stringler
- URL'ler, dosya yolları
- Error mesajları ve debug bilgileri

### 3. Hex Analizi
- Binary yapı incelemesi
- Gizli veriler arama
- Şifreleme belirtileri

### 4. İleri Analiz (Manuel)
- Disassembly (Ghidra, IDA Pro)
- Dynamic analysis (sandbox)
- Network traffic analizi

## Güvenlik Önlemleri

⚠️ **ÖNEMLİ**: Şüpheli .exe dosyalarını sadece izole edilmiş ortamda çalıştırın:
- Virtual machine kullanın
- Network bağlantısını kesin
- Snapshot alın

## Yaygın Bulgular

- **Packer**: UPX, ASPack belirtileri
- **Obfuscation**: String şifreleme
- **Malware**: Suspicious API calls
- **Legitimate**: Normal PE yapısı