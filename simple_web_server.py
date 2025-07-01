#!/usr/bin/env python3
"""
Simple Web Interface for Reverse Engineering Tools
Pure Python implementation without external dependencies
"""

import http.server
import socketserver
import urllib.parse
import json
import os
import tempfile
import sys
from pathlib import Path

# Add tools directory to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'tools'))

class REWebHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
    
    def do_GET(self):
        """Handle GET requests"""
        if self.path == '/' or self.path == '/index.html':
            self.serve_main_page()
        elif self.path == '/interactive':
            self.serve_interactive_page()
        elif self.path.startswith('/static/'):
            # Serve static files
            super().do_GET()
        else:
            super().do_GET()
    
    def do_POST(self):
        """Handle POST requests"""
        if self.path == '/api/analyze':
            self.handle_analyze()
        elif self.path == '/api/disassemble':
            self.handle_disassemble()
        elif self.path == '/api/hex_view':
            self.handle_hex_view()
        else:
            self.send_error(404, "Not Found")
    
    def serve_main_page(self):
        """Serve main page"""
        html_content = '''<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reverse Engineering Analysis Tool</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        .upload-area {
            border: 2px dashed #007bff;
            border-radius: 10px;
            padding: 40px;
            text-align: center;
            margin: 20px 0;
            transition: all 0.3s ease;
        }
        .upload-area:hover {
            border-color: #0056b3;
            background-color: #f8f9fa;
        }
        .file-icon {
            font-size: 48px;
            color: #007bff;
            margin-bottom: 15px;
        }
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
        <div class="container">
            <a class="navbar-brand" href="/">
                <i class="fas fa-search"></i> RE Analysis Tool
            </a>
            <div class="navbar-nav">
                <a class="nav-link" href="/interactive">
                    <i class="fas fa-code"></i> Interactive Analyzer
                </a>
            </div>
        </div>
    </nav>
    
    <div class="container mt-4">
        <div class="row">
            <div class="col-md-8 mx-auto">
                <div class="card">
                    <div class="card-header">
                        <h3><i class="fas fa-upload"></i> Dosya Yükle ve Analiz Et</h3>
                    </div>
                    <div class="card-body">
                        <form id="uploadForm" enctype="multipart/form-data">
                            <div class="upload-area" id="uploadArea">
                                <div class="file-icon">
                                    <i class="fas fa-cloud-upload-alt"></i>
                                </div>
                                <h5>Dosyanızı buraya sürükleyin veya tıklayın</h5>
                                <p class="text-muted">Desteklenen formatlar: .exe, .dll, .bin</p>
                                <input type="file" name="file" id="fileInput" accept=".exe,.dll,.bin" style="display: none;">
                                <button type="button" class="btn btn-primary" onclick="document.getElementById('fileInput').click();">
                                    <i class="fas fa-folder-open"></i> Dosya Seç
                                </button>
                                <a href="/interactive" class="btn btn-outline-info ms-2">
                                    <i class="fas fa-code"></i> Interactive Analyzer
                                </a>
                            </div>
                            
                            <div id="fileInfo" style="display: none;" class="mt-3">
                                <div class="alert alert-info">
                                    <strong>Seçilen dosya:</strong> <span id="fileName"></span>
                                </div>
                            </div>
                            
                            <div class="text-center mt-3">
                                <button type="submit" class="btn btn-success btn-lg" id="analyzeBtn" disabled>
                                    <i class="fas fa-cogs"></i> Analiz Başlat
                                </button>
                            </div>
                        </form>
                        
                        <div id="loadingIndicator" style="display: none;" class="mt-3">
                            <div class="text-center">
                                <div class="spinner-border" role="status">
                                    <span class="visually-hidden">Analiz yapılıyor...</span>
                                </div>
                                <p class="mt-2">Dosya analiz ediliyor...</p>
                            </div>
                        </div>
                        
                        <div id="results" style="display: none;" class="mt-4">
                            <div class="card">
                                <div class="card-header">
                                    <h5>Analiz Sonuçları</h5>
                                </div>
                                <div class="card-body">
                                    <div id="resultContent"></div>
                                    <div class="mt-3">
                                        <button class="btn btn-primary" onclick="downloadReport()">
                                            <i class="fas fa-download"></i> Raporu İndir
                                        </button>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="card mt-4">
                    <div class="card-header">
                        <h4><i class="fas fa-info-circle"></i> Özellikler</h4>
                    </div>
                    <div class="card-body">
                        <div class="row">
                            <div class="col-md-6">
                                <ul class="list-group list-group-flush">
                                    <li class="list-group-item"><i class="fas fa-check text-success"></i> PE Header Analizi</li>
                                    <li class="list-group-item"><i class="fas fa-check text-success"></i> Section Analizi</li>
                                    <li class="list-group-item"><i class="fas fa-check text-success"></i> Import/Export Tables</li>
                                    <li class="list-group-item"><i class="fas fa-check text-success"></i> Entropy Hesaplama</li>
                                    <li class="list-group-item"><i class="fas fa-check text-success"></i> Function Detection</li>
                                </ul>
                            </div>
                            <div class="col-md-6">
                                <ul class="list-group list-group-flush">
                                    <li class="list-group-item"><i class="fas fa-check text-success"></i> Packer Detection</li>
                                    <li class="list-group-item"><i class="fas fa-check text-success"></i> YARA Rules</li>
                                    <li class="list-group-item"><i class="fas fa-check text-success"></i> String Extraction</li>
                                    <li class="list-group-item"><i class="fas fa-check text-success"></i> Cross-References</li>
                                    <li class="list-group-item"><i class="fas fa-check text-success"></i> Interactive Hex Viewer</li>
                                </ul>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        let currentResults = null;
        
        document.getElementById('fileInput').addEventListener('change', function(e) {
            const file = e.target.files[0];
            if (file) {
                document.getElementById('fileName').textContent = file.name;
                document.getElementById('fileInfo').style.display = 'block';
                document.getElementById('analyzeBtn').disabled = false;
            }
        });
        
        document.getElementById('uploadForm').addEventListener('submit', function(e) {
            e.preventDefault();
            analyzeFile();
        });
        
        function analyzeFile() {
            const fileInput = document.getElementById('fileInput');
            const file = fileInput.files[0];
            
            if (!file) {
                alert('Lütfen bir dosya seçin');
                return;
            }
            
            document.getElementById('loadingIndicator').style.display = 'block';
            document.getElementById('results').style.display = 'none';
            
            const formData = new FormData();
            formData.append('file', file);
            
            fetch('/api/analyze', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                document.getElementById('loadingIndicator').style.display = 'none';
                
                if (data.success) {
                    currentResults = data.data;
                    displayResults(data.data);
                    document.getElementById('results').style.display = 'block';
                } else {
                    alert('Analiz başarısız: ' + data.error);
                }
            })
            .catch(error => {
                document.getElementById('loadingIndicator').style.display = 'none';
                alert('Hata: ' + error.message);
            });
        }
        
        function displayResults(data) {
            const content = document.getElementById('resultContent');
            let html = '';
            
            // File info
            if (data.pe_info && data.pe_info.file_info) {
                const fileInfo = data.pe_info.file_info;
                html += `<h6>Dosya Bilgileri</h6>
                <ul class="list-group list-group-flush mb-3">
                    <li class="list-group-item">Boyut: ${fileInfo.file_size.toLocaleString()} bytes</li>
                    <li class="list-group-item">MD5: ${fileInfo.md5}</li>
                    <li class="list-group-item">SHA256: ${fileInfo.sha256}</li>
                </ul>`;
            }
            
            // PE Info
            if (data.pe_info && data.pe_info.pe_header) {
                const peHeader = data.pe_info.pe_header;
                html += `<h6>PE Header</h6>
                <ul class="list-group list-group-flush mb-3">
                    <li class="list-group-item">Machine: ${peHeader.machine_type}</li>
                    <li class="list-group-item">Sections: ${peHeader.number_of_sections}</li>
                    <li class="list-group-item">Entry Point: 0x${data.pe_info.entry_point || 'N/A'}</li>
                </ul>`;
            }
            
            // Sections
            if (data.pe_info && data.pe_info.sections) {
                html += `<h6>Sections (${data.pe_info.sections.length})</h6>
                <div class="table-responsive">
                    <table class="table table-sm">
                        <thead>
                            <tr><th>Name</th><th>Virtual Size</th><th>Entropy</th></tr>
                        </thead>
                        <tbody>`;
                
                data.pe_info.sections.forEach(section => {
                    const entropy = section.entropy ? section.entropy.toFixed(2) : 'N/A';
                    const entropyClass = section.entropy > 7 ? 'text-danger' : (section.entropy > 6 ? 'text-warning' : 'text-success');
                    html += `<tr>
                        <td>${section.name}</td>
                        <td>${section.virtual_size.toLocaleString()}</td>
                        <td class="${entropyClass}">${entropy}</td>
                    </tr>`;
                });
                
                html += `</tbody></table></div>`;
            }
            
            // YARA Results
            if (data.yara_results && data.yara_results.length > 0) {
                html += `<h6 class="text-danger">YARA Detection (${data.yara_results.length})</h6>
                <ul class="list-group list-group-flush mb-3">`;
                
                data.yara_results.forEach(result => {
                    html += `<li class="list-group-item list-group-item-warning">
                        <strong>${result.rule_name}</strong><br>
                        <small>Matches: ${result.matches.join(', ')}</small>
                    </li>`;
                });
                
                html += `</ul>`;
            } else {
                html += `<div class="alert alert-success">✅ YARA: Hiçbir kural tetiklenmedi</div>`;
            }
            
            // Strings
            if (data.strings) {
                html += `<h6>String İstatistikleri</h6>
                <ul class="list-group list-group-flush mb-3">
                    <li class="list-group-item">ASCII Strings: ${data.strings.ascii_count}</li>
                    <li class="list-group-item">Unicode Strings: ${data.strings.unicode_count}</li>
                </ul>`;
            }
            
            content.innerHTML = html;
        }
        
        function downloadReport() {
            if (!currentResults) return;
            
            const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(currentResults, null, 2));
            const downloadAnchor = document.createElement('a');
            downloadAnchor.setAttribute("href", dataStr);
            downloadAnchor.setAttribute("download", "analysis_report.json");
            document.body.appendChild(downloadAnchor);
            downloadAnchor.click();
            downloadAnchor.remove();
        }
        
        // Drag and drop
        const uploadArea = document.getElementById('uploadArea');
        const fileInput = document.getElementById('fileInput');
        
        uploadArea.addEventListener('click', () => fileInput.click());
        
        uploadArea.addEventListener('dragover', (e) => {
            e.preventDefault();
            uploadArea.style.borderColor = '#0056b3';
            uploadArea.style.backgroundColor = '#f8f9fa';
        });
        
        uploadArea.addEventListener('dragleave', (e) => {
            e.preventDefault();
            uploadArea.style.borderColor = '#007bff';
            uploadArea.style.backgroundColor = '';
        });
        
        uploadArea.addEventListener('drop', (e) => {
            e.preventDefault();
            const files = e.dataTransfer.files;
            if (files.length > 0) {
                fileInput.files = files;
                const event = new Event('change', { bubbles: true });
                fileInput.dispatchEvent(event);
            }
            uploadArea.style.borderColor = '#007bff';
            uploadArea.style.backgroundColor = '';
        });
    </script>
</body>
</html>'''
        
        self.send_response(200)
        self.send_header('Content-type', 'text/html; charset=utf-8')
        self.end_headers()
        self.wfile.write(html_content.encode('utf-8'))
    
    def serve_interactive_page(self):
        """Serve interactive analyzer page"""
        html_content = '''<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Interactive Analyzer</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        .code-view {
            font-family: 'Courier New', monospace;
            font-size: 12px;
            background: #1e1e1e;
            color: #d4d4d4;
            padding: 10px;
            border-radius: 4px;
            max-height: 600px;
            overflow-y: auto;
        }
        .hex-view {
            font-family: 'Courier New', monospace;
            font-size: 12px;
            background: #1e1e1e;
            color: #d4d4d4;
            padding: 10px;
            border-radius: 4px;
            max-height: 600px;
            overflow-y: auto;
            white-space: pre;
        }
        .address { color: #569cd6; }
        .mnemonic { color: #4ec9b0; font-weight: bold; }
        .operand { color: #ce9178; }
        .hex-bytes { color: #b5cea8; }
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
        <div class="container">
            <a class="navbar-brand" href="/">
                <i class="fas fa-search"></i> RE Analysis Tool
            </a>
            <div class="navbar-nav">
                <a class="nav-link" href="/">
                    <i class="fas fa-home"></i> Ana Sayfa
                </a>
            </div>
        </div>
    </nav>
    
    <div class="container-fluid mt-4">
        <div class="card">
            <div class="card-header">
                <h3><i class="fas fa-code"></i> Interactive Binary Analyzer</h3>
                <input type="file" class="form-control mt-2" id="binaryFile" accept=".exe,.dll,.bin">
            </div>
            <div class="card-body">
                <ul class="nav nav-tabs" id="analysisTabs">
                    <li class="nav-item">
                        <a class="nav-link active" data-bs-toggle="tab" href="#hex-tab">
                            <i class="fas fa-table"></i> Hex View
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" data-bs-toggle="tab" href="#disasm-tab">
                            <i class="fas fa-microchip"></i> Disassembly
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" data-bs-toggle="tab" href="#info-tab">
                            <i class="fas fa-info"></i> File Info
                        </a>
                    </li>
                </ul>
                
                <div class="tab-content mt-3">
                    <div class="tab-pane fade show active" id="hex-tab">
                        <div class="row mb-3">
                            <div class="col-md-3">
                                <input type="text" class="form-control" id="hexOffset" placeholder="Offset (0)" value="0">
                            </div>
                            <div class="col-md-3">
                                <input type="text" class="form-control" id="hexSize" placeholder="Size (512)" value="512">
                            </div>
                            <div class="col-md-3">
                                <button class="btn btn-primary" onclick="updateHexView()">Update</button>
                            </div>
                        </div>
                        <div id="hexContent" class="hex-view">Select a file to view hex dump...</div>
                    </div>
                    
                    <div class="tab-pane fade" id="disasm-tab">
                        <div id="disasmContent" class="code-view">Select a file to view disassembly...</div>
                    </div>
                    
                    <div class="tab-pane fade" id="info-tab">
                        <div id="infoContent">Select a file to view information...</div>
                    </div>
                </div>
                
                <div id="loadingIndicator" style="display: none;" class="text-center mt-3">
                    <div class="spinner-border" role="status"></div>
                    <p class="mt-2">Analyzing...</p>
                </div>
            </div>
        </div>
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        let currentFile = null;
        
        document.getElementById('binaryFile').addEventListener('change', function(e) {
            currentFile = e.target.files[0];
            if (currentFile) {
                updateHexView();
                analyzeFile();
            }
        });
        
        function updateHexView() {
            if (!currentFile) return;
            
            const offset = parseInt(document.getElementById('hexOffset').value || '0');
            const size = parseInt(document.getElementById('hexSize').value || '512');
            
            const formData = new FormData();
            formData.append('file', currentFile);
            formData.append('offset', offset);
            formData.append('size', size);
            
            fetch('/api/hex_view', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    let content = '';
                    data.hex_lines.forEach(line => {
                        content += line.data + '\\n';
                    });
                    document.getElementById('hexContent').textContent = content;
                }
            })
            .catch(error => console.error('Error:', error));
        }
        
        function analyzeFile() {
            if (!currentFile) return;
            
            document.getElementById('loadingIndicator').style.display = 'block';
            
            const formData = new FormData();
            formData.append('file', currentFile);
            
            fetch('/api/analyze', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                document.getElementById('loadingIndicator').style.display = 'none';
                if (data.success) {
                    updateInfoTab(data.data);
                }
            })
            .catch(error => {
                document.getElementById('loadingIndicator').style.display = 'none';
                console.error('Error:', error);
            });
        }
        
        function updateInfoTab(data) {
            let html = '<div class="row">';
            
            // File info
            if (data.pe_info && data.pe_info.file_info) {
                const fileInfo = data.pe_info.file_info;
                html += `<div class="col-md-6">
                    <h5>File Information</h5>
                    <table class="table table-sm">
                        <tr><td>Size</td><td>${fileInfo.file_size.toLocaleString()} bytes</td></tr>
                        <tr><td>MD5</td><td><small>${fileInfo.md5}</small></td></tr>
                        <tr><td>SHA256</td><td><small>${fileInfo.sha256}</small></td></tr>
                    </table>
                </div>`;
            }
            
            // PE sections
            if (data.pe_info && data.pe_info.sections) {
                html += `<div class="col-md-6">
                    <h5>PE Sections</h5>
                    <table class="table table-sm">
                        <thead><tr><th>Name</th><th>Size</th><th>Entropy</th></tr></thead>
                        <tbody>`;
                
                data.pe_info.sections.forEach(section => {
                    const entropy = section.entropy ? section.entropy.toFixed(2) : 'N/A';
                    html += `<tr>
                        <td>${section.name}</td>
                        <td>${section.virtual_size.toLocaleString()}</td>
                        <td>${entropy}</td>
                    </tr>`;
                });
                
                html += `</tbody></table></div>`;
            }
            
            html += '</div>';
            document.getElementById('infoContent').innerHTML = html;
        }
    </script>
</body>
</html>'''
        
        self.send_response(200)
        self.send_header('Content-type', 'text/html; charset=utf-8')
        self.end_headers()
        self.wfile.write(html_content.encode('utf-8'))
    
    def handle_analyze(self):
        """Handle file analysis"""
        try:
            # Parse multipart form data
            content_type = self.headers.get('Content-Type', '')
            if not content_type.startswith('multipart/form-data'):
                self.send_json_response({'error': 'Invalid content type'}, 400)
                return
            
            # Get boundary
            boundary = content_type.split('boundary=')[1].encode()
            
            # Read POST data
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            
            # Simple multipart parsing
            parts = post_data.split(b'--' + boundary)
            file_data = None
            
            for part in parts:
                if b'filename=' in part and b'Content-Type:' in part:
                    # Extract file data
                    data_start = part.find(b'\r\n\r\n') + 4
                    if data_start > 3:
                        file_data = part[data_start:-2]  # Remove trailing \r\n
                        break
            
            if not file_data:
                self.send_json_response({'error': 'No file data found'}, 400)
                return
            
            # Save to temporary file and analyze
            with tempfile.NamedTemporaryFile(delete=False, suffix='.exe') as tmp_file:
                tmp_file.write(file_data)
                tmp_path = tmp_file.name
            
            try:
                # Basic PE analysis
                result = self.analyze_pe_file(tmp_path)
                self.send_json_response({'success': True, 'data': result})
            finally:
                os.unlink(tmp_path)
                
        except Exception as e:
            self.send_json_response({'error': str(e)}, 500)
    
    def handle_hex_view(self):
        """Handle hex view request"""
        try:
            # Parse multipart form data (simplified)
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            
            # Extract file and parameters
            boundary = self.headers.get('Content-Type', '').split('boundary=')[1].encode()
            parts = post_data.split(b'--' + boundary)
            
            file_data = None
            offset = 0
            size = 512
            
            for part in parts:
                if b'name="file"' in part and b'filename=' in part:
                    data_start = part.find(b'\r\n\r\n') + 4
                    if data_start > 3:
                        file_data = part[data_start:-2]
                elif b'name="offset"' in part:
                    data_start = part.find(b'\r\n\r\n') + 4
                    if data_start > 3:
                        offset = int(part[data_start:-2].decode())
                elif b'name="size"' in part:
                    data_start = part.find(b'\r\n\r\n') + 4
                    if data_start > 3:
                        size = int(part[data_start:-2].decode())
            
            if not file_data:
                self.send_json_response({'error': 'No file data'}, 400)
                return
            
            # Generate hex view
            hex_lines = []
            end_offset = min(offset + size, len(file_data))
            
            for line_offset in range(offset, end_offset, 16):
                line_data = file_data[line_offset:line_offset + 16]
                
                # Format hex line
                hex_part = ' '.join(f'{b:02x}' for b in line_data)
                ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in line_data)
                
                hex_line = f"{line_offset:08x}: {hex_part:<48} |{ascii_part}|"
                hex_lines.append({
                    'offset': line_offset,
                    'data': hex_line
                })
            
            self.send_json_response({
                'success': True,
                'hex_lines': hex_lines,
                'file_size': len(file_data),
                'offset': offset,
                'size': len(hex_lines) * 16
            })
            
        except Exception as e:
            self.send_json_response({'error': str(e)}, 500)
    
    def handle_disassemble(self):
        """Handle disassemble request - simplified version"""
        self.send_json_response({
            'success': True,
            'data': {
                'functions': {},
                'pe_info': {'entry_point': '0x401000'},
                'message': 'Disassembly requires capstone library'
            }
        })
    
    def analyze_pe_file(self, file_path):
        """Basic PE file analysis"""
        try:
            import struct
            import hashlib
            import math
            from collections import Counter
            
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            file_size = len(file_data)
            
            # File hashes
            md5_hash = hashlib.md5(file_data).hexdigest()
            sha256_hash = hashlib.sha256(file_data).hexdigest()
            
            # Basic PE check
            if file_size < 64 or file_data[:2] != b'MZ':
                return {
                    'pe_info': {
                        'valid_pe': False,
                        'file_info': {
                            'file_size': file_size,
                            'md5': md5_hash,
                            'sha256': sha256_hash
                        }
                    }
                }
            
            # DOS header
            pe_offset = struct.unpack('<I', file_data[60:64])[0]
            
            if pe_offset >= file_size - 4 or file_data[pe_offset:pe_offset+4] != b'PE\x00\x00':
                return {
                    'pe_info': {
                        'valid_pe': False,
                        'file_info': {
                            'file_size': file_size,
                            'md5': md5_hash,
                            'sha256': sha256_hash
                        }
                    }
                }
            
            # PE header
            pe_header_offset = pe_offset + 4
            machine = struct.unpack('<H', file_data[pe_header_offset:pe_header_offset+2])[0]
            section_count = struct.unpack('<H', file_data[pe_header_offset+2:pe_header_offset+4])[0]
            
            machine_types = {
                0x14c: 'i386',
                0x8664: 'x86_64',
                0x1c0: 'ARM',
                0xaa64: 'ARM64'
            }
            
            # Sections
            opt_header_size = struct.unpack('<H', file_data[pe_offset+20:pe_offset+22])[0]
            section_table_offset = pe_offset + 24 + opt_header_size
            
            sections = []
            for i in range(min(section_count, 10)):  # Limit sections
                section_offset = section_table_offset + (i * 40)
                if section_offset + 40 > file_size:
                    break
                
                section_data = file_data[section_offset:section_offset+40]
                section = {
                    'name': section_data[:8].rstrip(b'\x00').decode('ascii', errors='ignore'),
                    'virtual_size': struct.unpack('<I', section_data[8:12])[0],
                    'virtual_address': struct.unpack('<I', section_data[12:16])[0],
                    'size_of_raw_data': struct.unpack('<I', section_data[16:20])[0],
                    'pointer_to_raw_data': struct.unpack('<I', section_data[20:24])[0]
                }
                
                # Calculate entropy
                if (section['pointer_to_raw_data'] > 0 and 
                    section['size_of_raw_data'] > 0 and
                    section['pointer_to_raw_data'] + section['size_of_raw_data'] <= file_size):
                    
                    start = section['pointer_to_raw_data']
                    end = start + section['size_of_raw_data']
                    section_bytes = file_data[start:end]
                    
                    if section_bytes:
                        byte_counts = Counter(section_bytes)
                        entropy = 0
                        data_len = len(section_bytes)
                        
                        for count in byte_counts.values():
                            probability = count / data_len
                            if probability > 0:
                                entropy += -probability * math.log2(probability)
                        
                        section['entropy'] = entropy
                
                sections.append(section)
            
            # Simple YARA-like checks
            yara_results = []
            
            # Check for UPX
            if b'UPX!' in file_data or b'UPX0' in file_data:
                yara_results.append({
                    'rule_name': 'UPX_Packer',
                    'matches': ['UPX signature']
                })
            
            # Check for high entropy sections
            high_entropy_sections = [s['name'] for s in sections if s.get('entropy', 0) > 7.0]
            if high_entropy_sections:
                yara_results.append({
                    'rule_name': 'High_Entropy_Sections',
                    'matches': high_entropy_sections
                })
            
            # String extraction (simple)
            import re
            ascii_strings = re.findall(rb'[\x20-\x7E]{4,}', file_data)
            unicode_strings = re.findall(rb'(?:[\x20-\x7E]\x00){4,}', file_data)
            
            return {
                'pe_info': {
                    'valid_pe': True,
                    'file_info': {
                        'file_size': file_size,
                        'md5': md5_hash,
                        'sha256': sha256_hash
                    },
                    'pe_header': {
                        'machine_type': machine_types.get(machine, f'Unknown (0x{machine:x})'),
                        'number_of_sections': section_count
                    },
                    'sections': sections,
                    'entry_point': None  # Would need optional header parsing
                },
                'yara_results': yara_results,
                'strings': {
                    'ascii_count': len(ascii_strings),
                    'unicode_count': len(unicode_strings),
                    'ascii_sample': [s.decode('ascii', errors='ignore') for s in ascii_strings[:20]],
                    'unicode_sample': [s.decode('utf-16le', errors='ignore') for s in unicode_strings[:20]]
                }
            }
            
        except Exception as e:
            return {'error': f'Analysis failed: {e}'}
    
    def send_json_response(self, data, status=200):
        """Send JSON response"""
        json_data = json.dumps(data, ensure_ascii=False).encode('utf-8')
        
        self.send_response(status)
        self.send_header('Content-type', 'application/json; charset=utf-8')
        self.send_header('Content-length', str(len(json_data)))
        self.end_headers()
        self.wfile.write(json_data)

def main():
    PORT = 8000
    
    print(f"🌐 Starting Reverse Engineering Web Interface...")
    print(f"📍 Server: http://localhost:{PORT}")
    print(f"🔍 Main Page: http://localhost:{PORT}/")
    print(f"⚡ Interactive: http://localhost:{PORT}/interactive")
    print(f"⚠️  Press Ctrl+C to stop the server")
    print("=" * 60)
    
    try:
        with socketserver.TCPServer(("", PORT), REWebHandler) as httpd:
            httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n🛑 Server stopped by user")
    except Exception as e:
        print(f"❌ Server error: {e}")

if __name__ == "__main__":
    main()