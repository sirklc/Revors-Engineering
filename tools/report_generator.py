#!/usr/bin/env python3
"""
Report Generator
Analiz sonuçlarını HTML ve JSON formatında rapor et
"""

import sys
import os
import json
import hashlib
from datetime import datetime
from tools.pe_analyzer import PEAnalyzer
from tools.import_analyzer import ImportExportAnalyzer  
from tools.yara_scanner import YaraScanner
from tools.strings_extractor import StringExtractor

class ReportGenerator:
    def __init__(self, file_path):
        self.file_path = file_path
        self.file_name = os.path.basename(file_path)
        self.analysis_data = {}
        
    def run_all_analysis(self):
        """Tüm analizleri çalıştır"""
        print("🔄 Kapsamlı analiz başlatılıyor...")
        
        # PE Analysis
        print("  📋 PE analizi...")
        pe_analyzer = PEAnalyzer(self.file_path)
        if pe_analyzer.load_file():
            pe_analyzer.parse_dos_header()
            pe_analyzer.parse_pe_header()
            pe_analyzer.parse_sections()
            
            self.analysis_data['pe_info'] = {
                'valid_pe': pe_analyzer.check_pe_signature(),
                'file_info': pe_analyzer.get_file_info(),
                'dos_header': pe_analyzer.dos_header,
                'pe_header': pe_analyzer.pe_header,
                'sections': pe_analyzer.sections,
                'packer_info': pe_analyzer.detect_packer(),
                'overall_entropy': pe_analyzer.calculate_entropy(pe_analyzer.file_data)
            }
        
        # Import Analysis
        print("  📦 Import analizi...")
        import_analyzer = ImportExportAnalyzer(self.file_path)
        if import_analyzer.load_file():
            import_analyzer.get_pe_offset()
            import_analyzer.parse_imports()
            
            self.analysis_data['imports'] = {
                'dlls': import_analyzer.imports,
                'suspicious_apis': import_analyzer.analyze_suspicious_imports()
            }
        
        # YARA Scanning
        print("  🔍 YARA taraması...")
        yara_scanner = YaraScanner(self.file_path)
        if yara_scanner.load_file():
            results = yara_scanner.scan_all_rules()
            self.analysis_data['yara_results'] = results
        
        # String Extraction
        print("  📝 String çıkarma...")
        string_extractor = StringExtractor(self.file_path, min_length=4)
        if string_extractor.load_file():
            with open(self.file_path, 'rb') as f:
                data = f.read()
            ascii_strings = string_extractor.extract_ascii_strings(data)
            unicode_strings = string_extractor.extract_unicode_strings(data)
            
            self.analysis_data['strings'] = {
                'ascii_count': len(ascii_strings),
                'unicode_count': len(unicode_strings),
                'ascii_sample': ascii_strings[:50],
                'unicode_sample': unicode_strings[:50]
            }
        
        # Analysis metadata
        self.analysis_data['metadata'] = {
            'file_path': self.file_path,
            'file_name': self.file_name,
            'analysis_time': datetime.now().isoformat(),
            'tool_version': '1.0'
        }
        
        print("✅ Analiz tamamlandı!")
        
    def generate_json_report(self, output_path):
        """JSON raporu oluştur"""
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(self.analysis_data, f, indent=2, ensure_ascii=False, default=str)
            return True
        except Exception as e:
            print(f"JSON raporu oluşturulamadı: {e}")
            return False
    
    def generate_html_report(self, output_path):
        """HTML raporu oluştur"""
        try:
            html_content = self._create_html_content()
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            return True
        except Exception as e:
            print(f"HTML raporu oluşturulamadı: {e}")
            return False
    
    def _create_html_content(self):
        """HTML içeriği oluştur"""
        data = self.analysis_data
        
        html = f'''<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RE Analiz Raporu - {self.file_name}</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .header {{ text-align: center; border-bottom: 2px solid #007acc; padding-bottom: 20px; margin-bottom: 30px; }}
        .section {{ margin: 20px 0; padding: 20px; border: 1px solid #ddd; border-radius: 5px; }}
        .section h2 {{ color: #007acc; margin-top: 0; }}
        .info-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 10px; }}
        .info-item {{ background: #f8f9fa; padding: 10px; border-radius: 3px; }}
        .info-label {{ font-weight: bold; color: #555; }}
        .section-table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
        .section-table th, .section-table td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        .section-table th {{ background: #007acc; color: white; }}
        .warning {{ background: #fff3cd; border: 1px solid #ffeaa7; color: #856404; padding: 10px; border-radius: 3px; }}
        .success {{ background: #d4edda; border: 1px solid #c3e6cb; color: #155724; padding: 10px; border-radius: 3px; }}
        .danger {{ background: #f8d7da; border: 1px solid #f5c6cb; color: #721c24; padding: 10px; border-radius: 3px; }}
        .entropy-high {{ color: #dc3545; font-weight: bold; }}
        .entropy-medium {{ color: #ffc107; font-weight: bold; }}
        .entropy-low {{ color: #28a745; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Reverse Engineering Analiz Raporu</h1>
            <h2>{self.file_name}</h2>
            <p>Analiz Tarihi: {data.get('metadata', {}).get('analysis_time', 'N/A')}</p>
        </div>
'''
        
        # File Info Section
        if 'pe_info' in data and data['pe_info'].get('file_info'):
            file_info = data['pe_info']['file_info']
            html += f'''
        <div class="section">
            <h2>📁 Dosya Bilgileri</h2>
            <div class="info-grid">
                <div class="info-item">
                    <div class="info-label">Boyut:</div>
                    {file_info['file_size']:,} bytes
                </div>
                <div class="info-item">
                    <div class="info-label">MD5:</div>
                    {file_info['md5']}
                </div>
                <div class="info-item">
                    <div class="info-label">SHA1:</div>
                    {file_info['sha1']}
                </div>
                <div class="info-item">
                    <div class="info-label">SHA256:</div>
                    {file_info['sha256']}
                </div>
            </div>
        </div>
'''

        # PE Header Section
        if 'pe_info' in data and data['pe_info'].get('pe_header'):
            pe_header = data['pe_info']['pe_header']
            validity = "✅ Geçerli PE" if data['pe_info'].get('valid_pe') else "❌ Geçersiz PE"
            html += f'''
        <div class="section">
            <h2>🔧 PE Header Bilgileri</h2>
            <div class="{('success' if data['pe_info'].get('valid_pe') else 'danger')}">{validity}</div>
            <div class="info-grid">
                <div class="info-item">
                    <div class="info-label">Makine Tipi:</div>
                    {pe_header.get('machine_type', 'N/A')}
                </div>
                <div class="info-item">
                    <div class="info-label">Section Sayısı:</div>
                    {pe_header.get('number_of_sections', 'N/A')}
                </div>
                <div class="info-item">
                    <div class="info-label">Timestamp:</div>
                    {datetime.fromtimestamp(pe_header.get('time_date_stamp', 0)) if pe_header.get('time_date_stamp') else 'N/A'}
                </div>
            </div>
        </div>
'''

        # Sections
        if 'pe_info' in data and data['pe_info'].get('sections'):
            sections = data['pe_info']['sections']
            html += f'''
        <div class="section">
            <h2>📊 Sections ({len(sections)} adet)</h2>
            <table class="section-table">
                <tr>
                    <th>İsim</th>
                    <th>Virtual Size</th>
                    <th>Virtual Address</th>
                    <th>Raw Size</th>
                    <th>Entropy</th>
                </tr>
'''
            for section in sections:
                entropy = section.get('entropy', 0)
                entropy_class = 'entropy-high' if entropy > 7.0 else ('entropy-medium' if entropy > 6.0 else 'entropy-low')
                html += f'''
                <tr>
                    <td>{section.get('name', 'N/A')}</td>
                    <td>{section.get('virtual_size', 0):,}</td>
                    <td>0x{section.get('virtual_address', 0):08x}</td>
                    <td>{section.get('size_of_raw_data', 0):,}</td>
                    <td class="{entropy_class}">{entropy:.2f}</td>
                </tr>
'''
            html += '            </table>\n        </div>\n'

        # Packer Detection
        if 'pe_info' in data and data['pe_info'].get('packer_info'):
            packer_info = data['pe_info']['packer_info']
            prob = packer_info.get('packed_probability', 0)
            prob_class = 'danger' if prob > 0.5 else ('warning' if prob > 0.2 else 'success')
            
            html += f'''
        <div class="section">
            <h2>🔍 Packer Detection</h2>
            <div class="{prob_class}">
                Packed Probability: {prob:.2%}
            </div>
'''
            if packer_info.get('suspicious_sections'):
                html += f"<p><strong>Şüpheli Sections:</strong> {', '.join(packer_info['suspicious_sections'])}</p>"
            if packer_info.get('high_entropy_sections'):
                html += f"<p><strong>Yüksek Entropy Sections:</strong> {', '.join(packer_info['high_entropy_sections'])}</p>"
            html += '        </div>\n'

        # YARA Results
        if 'yara_results' in data and data['yara_results']:
            html += f'''
        <div class="section">
            <h2>🎯 YARA Dedection Sonuçları</h2>
            <div class="danger">⚠️ {len(data['yara_results'])} kural tetiklendi</div>
'''
            for result in data['yara_results']:
                html += f'''
            <div class="warning">
                <strong>{result['rule_name']}</strong><br>
                Matches: {', '.join(result['matches'])}
            </div>
'''
            html += '        </div>\n'
        else:
            html += '''
        <div class="section">
            <h2>🎯 YARA Detection Sonuçları</h2>
            <div class="success">✅ Hiçbir YARA kuralı tetiklenmedi</div>
        </div>
'''

        # Imports
        if 'imports' in data and data['imports'].get('dlls'):
            dlls = data['imports']['dlls']
            total_funcs = sum(len(dll['functions']) for dll in dlls)
            
            html += f'''
        <div class="section">
            <h2>📦 Import Table ({len(dlls)} DLL, {total_funcs} fonksiyon)</h2>
'''
            for dll in dlls[:10]:  # İlk 10 DLL
                html += f'''
            <h4>{dll['dll']} ({len(dll['functions'])} fonksiyon)</h4>
            <p>{', '.join(dll['functions'][:20])}{'...' if len(dll['functions']) > 20 else ''}</p>
'''
            html += '        </div>\n'

        # Suspicious APIs
        if 'imports' in data and data['imports'].get('suspicious_apis'):
            suspicious = data['imports']['suspicious_apis']
            if suspicious:
                html += '''
        <div class="section">
            <h2>⚠️ Şüpheli API Çağrıları</h2>
'''
                for category, apis in suspicious.items():
                    html += f'            <h4>{category}</h4>\n            <ul>\n'
                    for dll, func in apis:
                        html += f'                <li>{dll} → {func}</li>\n'
                    html += '            </ul>\n'
                html += '        </div>\n'

        # String Statistics
        if 'strings' in data:
            strings_info = data['strings']
            html += f'''
        <div class="section">
            <h2>📝 String İstatistikleri</h2>
            <div class="info-grid">
                <div class="info-item">
                    <div class="info-label">ASCII Strings:</div>
                    {strings_info.get('ascii_count', 0)}
                </div>
                <div class="info-item">
                    <div class="info-label">Unicode Strings:</div>
                    {strings_info.get('unicode_count', 0)}
                </div>
            </div>
        </div>
'''

        html += '''
    </div>
</body>
</html>'''
        
        return html
    
    def generate_reports(self, output_dir):
        """Hem JSON hem HTML raporu oluştur"""
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
            
        base_name = os.path.splitext(self.file_name)[0]
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        json_path = os.path.join(output_dir, f"{base_name}_report_{timestamp}.json")
        html_path = os.path.join(output_dir, f"{base_name}_report_{timestamp}.html")
        
        self.run_all_analysis()
        
        json_success = self.generate_json_report(json_path)
        html_success = self.generate_html_report(html_path)
        
        return {
            'json_path': json_path if json_success else None,
            'html_path': html_path if html_success else None
        }

def main():
    if len(sys.argv) < 2:
        print("Kullanım: python report_generator.py <exe_dosyasi> [output_dir]")
        sys.exit(1)
    
    file_path = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else "reports"
    
    if not os.path.exists(file_path):
        print(f"Dosya bulunamadı: {file_path}")
        sys.exit(1)
    
    generator = ReportGenerator(file_path)
    results = generator.generate_reports(output_dir)
    
    print("\n📊 RAPOR OLUŞTURMA TAMAMLANDI")
    print("=" * 50)
    
    if results['json_path']:
        print(f"✅ JSON Raporu: {results['json_path']}")
    if results['html_path']:
        print(f"✅ HTML Raporu: {results['html_path']}")

if __name__ == "__main__":
    main()