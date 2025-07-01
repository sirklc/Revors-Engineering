#!/bin/bash

# Reverse Engineering Tools Launcher Script
# Bu script araçları kolayca başlatmanızı sağlar

echo "🔍 Reverse Engineering Tools Launcher"
echo "======================================"

# Dizin kontrolü
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "📁 Working directory: $SCRIPT_DIR"

# Python kontrolü
if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 bulunamadı. Lütfen Python3'ü kurun."
    exit 1
fi

echo "✅ Python3 found: $(python3 --version)"

# Menü
while true; do
    echo ""
    echo "🛠️  Araç Seçenekleri:"
    echo "1) 🌐 Web Arayüzü Başlat (Basit)"
    echo "2) 🚀 Flask Web Arayüzü Başlat (Gelişmiş)"
    echo "3) 📋 PE Analyzer"
    echo "4) 📝 Interactive Hex Viewer"
    echo "5) 🎯 Function Analyzer"
    echo "6) 🔗 Cross-Reference Analyzer"
    echo "7) 🔍 IDA-like Analyzer"
    echo "8) 📊 Generate Report"
    echo "9) 🌐 HTML Launcher Aç"
    echo "0) ❌ Çıkış"
    echo ""
    read -p "Seçiminizi yapın [0-9]: " choice

    case $choice in
        1)
            echo "🌐 Basit web arayüzü başlatılıyor..."
            echo "📍 Adres: http://localhost:8000"
            echo "⚠️  Kapatmak için Ctrl+C basın"
            python3 simple_web_server.py
            ;;
        2)
            echo "🚀 Flask web arayüzü başlatılıyor..."
            echo "📍 Adres: http://localhost:5000"
            echo "⚠️  Kapatmak için Ctrl+C basın"
            if python3 -c "import flask" 2>/dev/null; then
                python3 web_interface.py
            else
                echo "❌ Flask bulunamadı. Kurulum için:"
                echo "pip3 install Flask"
                echo ""
                echo "🔄 Basit web arayüzüne geçiliyor..."
                python3 simple_web_server.py
            fi
            ;;
        3)
            echo "📋 PE Analyzer başlatılıyor..."
            read -p "Dosya yolu girin: " file_path
            if [[ -f "$file_path" ]]; then
                python3 tools/pe_analyzer.py "$file_path"
            else
                echo "❌ Dosya bulunamadı: $file_path"
            fi
            read -p "Devam etmek için Enter'a basın..."
            ;;
        4)
            echo "📝 Interactive Hex Viewer başlatılıyor..."
            read -p "Dosya yolu girin: " file_path
            if [[ -f "$file_path" ]]; then
                python3 tools/hex_viewer.py "$file_path"
            else
                echo "❌ Dosya bulunamadı: $file_path"
            fi
            read -p "Devam etmek için Enter'a basın..."
            ;;
        5)
            echo "🎯 Function Analyzer başlatılıyor..."
            read -p "Dosya yolu girin: " file_path
            if [[ -f "$file_path" ]]; then
                python3 tools/function_analyzer.py "$file_path"
            else
                echo "❌ Dosya bulunamadı: $file_path"
            fi
            read -p "Devam etmek için Enter'a basın..."
            ;;
        6)
            echo "🔗 Cross-Reference Analyzer başlatılıyor..."
            read -p "Dosya yolu girin: " file_path
            if [[ -f "$file_path" ]]; then
                python3 tools/xref_analyzer.py "$file_path"
            else
                echo "❌ Dosya bulunamadı: $file_path"
            fi
            read -p "Devam etmek için Enter'a basın..."
            ;;
        7)
            echo "🔍 IDA-like Analyzer başlatılıyor..."
            read -p "Dosya yolu girin: " file_path
            if [[ -f "$file_path" ]]; then
                python3 tools/ida_like_analyzer.py "$file_path"
            else
                echo "❌ Dosya bulunamadı: $file_path"
            fi
            read -p "Devam etmek için Enter'a basın..."
            ;;
        8)
            echo "📊 Report Generator başlatılıyor..."
            read -p "Dosya yolu girin: " file_path
            if [[ -f "$file_path" ]]; then
                echo "📄 Rapor oluşturuluyor..."
                python3 tools/report_generator.py "$file_path" reports/
                echo "✅ Rapor reports/ klasörüne kaydedildi"
            else
                echo "❌ Dosya bulunamadı: $file_path"
            fi
            read -p "Devam etmek için Enter'a basın..."
            ;;
        9)
            echo "🌐 HTML Launcher açılıyor..."
            if command -v xdg-open &> /dev/null; then
                xdg-open "index.html"
            elif command -v firefox &> /dev/null; then
                firefox "index.html"
            elif command -v google-chrome &> /dev/null; then
                google-chrome "index.html"
            else
                echo "📁 Tarayıcı bulunamadı. Manuel olarak açın: index.html"
            fi
            ;;
        0)
            echo "👋 Çıkılıyor..."
            exit 0
            ;;
        *)
            echo "❌ Geçersiz seçim. Lütfen 0-9 arası bir sayı girin."
            ;;
    esac
done