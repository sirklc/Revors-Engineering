#!/bin/bash
# .exe dosyası için kapsamlı analiz scripti

if [ $# -eq 0 ]; then
    echo "Kullanım: ./analyze_exe.sh <exe_dosyasi>"
    exit 1
fi

EXE_FILE="$1"
BASE_NAME=$(basename "$EXE_FILE" .exe)
OUTPUT_DIR="output/${BASE_NAME}_analysis_$(date +%Y%m%d_%H%M%S)"

echo "🔍 === KAPSAMLI REVERSE ENGINEERING ANALİZİ ==="
echo "📁 Dosya: $EXE_FILE"
echo "📂 Çıktı dizini: $OUTPUT_DIR"
echo

# Çıktı dizini oluştur
mkdir -p "$OUTPUT_DIR"

echo "🔧 [1/11] Gelişmiş PE Analizi..."
python3 tools/pe_analyzer.py "$EXE_FILE" > "$OUTPUT_DIR/pe_analysis.txt"

echo "📦 [2/11] Import/Export Analizi..."
python3 tools/import_analyzer.py "$EXE_FILE" > "$OUTPUT_DIR/import_analysis.txt"

echo "🔍 [3/11] YARA Kuralları Tarama..."
python3 tools/yara_scanner.py "$EXE_FILE" > "$OUTPUT_DIR/yara_results.txt"

echo "📝 [4/11] String Çıkarma..."
python3 tools/strings_extractor.py "$EXE_FILE" > "$OUTPUT_DIR/strings.txt"

echo "🖥️  [5/11] Disassembly ve Source Kod Çıkarma..."
python3 tools/disassembler.py "$EXE_FILE" "$OUTPUT_DIR/source_code" > "$OUTPUT_DIR/disassembly.log"

echo "🔐 [6/11] Sertifika Analizi..."
python3 tools/certificate_extractor.py "$EXE_FILE" "$OUTPUT_DIR/certificates" > "$OUTPUT_DIR/certificate_analysis.txt"

echo "💾 [7/11] Memory Dump Analizi..."
python3 tools/memory_dump_analyzer.py "$EXE_FILE" "$OUTPUT_DIR/dumps" > "$OUTPUT_DIR/memory_analysis.txt"

echo "🔧 [8/11] File Structure Reconstruction..."
python3 tools/file_reconstructor.py "$EXE_FILE" "$OUTPUT_DIR/reconstructed" > "$OUTPUT_DIR/reconstruction.log"

echo "🎨 [9/11] Resource Extraction..."
python3 tools/resource_extractor.py "$EXE_FILE" "$OUTPUT_DIR/resources" > "$OUTPUT_DIR/resource_extraction.txt"

echo "📊 [10/11] Kapsamlı Rapor Oluşturma..."
python3 tools/report_generator.py "$EXE_FILE" "$OUTPUT_DIR" > "$OUTPUT_DIR/report_generation.log"

echo "🔢 [11/11] Hex Dump (ilk 2048 byte)..."
xxd -l 2048 "$EXE_FILE" > "$OUTPUT_DIR/hexdump.txt"

echo "ℹ️  Sistem Bilgileri topluyor..."
{
    echo "=== DOSYA BİLGİLERİ ==="
    file "$EXE_FILE"
    echo
    echo "=== DOSYA İSTATİSTİKLERİ ==="
    ls -la "$EXE_FILE"
    echo
    echo "=== HASH DEĞERLER ==="
    md5sum "$EXE_FILE"
    sha1sum "$EXE_FILE"
    sha256sum "$EXE_FILE"
    echo
    echo "=== ANALİZ TARİHİ ==="
    date
} > "$OUTPUT_DIR/file_info.txt"

echo
echo "✅ KAPSAMLI ANALİZ TAMAMLANDI!"
echo "=" * 50
echo "📂 Ana Sonuçlar: $OUTPUT_DIR"
echo
echo "📁 Çıkarılan İçerikler:"
echo "   🖥️  Source Code: $OUTPUT_DIR/source_code/"
echo "   🔐 Certificates: $OUTPUT_DIR/certificates/"
echo "   💾 Memory Dumps: $OUTPUT_DIR/dumps/"
echo "   🔧 Reconstructed: $OUTPUT_DIR/reconstructed/"
echo "   🎨 Resources: $OUTPUT_DIR/resources/"
echo
echo "📊 Raporlar:"
echo "   📄 HTML: find $OUTPUT_DIR -name '*.html'"
echo "   📋 JSON: find $OUTPUT_DIR -name '*.json'"
echo "   📝 Logs: $OUTPUT_DIR/*.txt"
echo
echo "🔧 Kullanışlı Komutlar:"
echo "   📋 Hızlı bakış: ls -la $OUTPUT_DIR"
echo "   🌐 HTML açma: find $OUTPUT_DIR -name '*.html' -exec open {} \;"
echo "   📖 Log okuma: cat $OUTPUT_DIR/*.txt | less"
echo "   🔍 Source kod: ls $OUTPUT_DIR/source_code/"
echo "   🎨 Resource'lar: ls $OUTPUT_DIR/resources/"