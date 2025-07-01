#!/usr/bin/env python3
"""
Web Interface for Reverse Engineering Tools
Flask tabanlı web arayüzü
"""

from flask import Flask, render_template, request, jsonify, send_file, flash, redirect, url_for
import os
import tempfile
import shutil
from werkzeug.utils import secure_filename
from tools.report_generator import ReportGenerator
import json

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this'
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max file size
app.config['UPLOAD_FOLDER'] = 'uploads'

# Upload folder oluştur
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs('reports', exist_ok=True)

ALLOWED_EXTENSIONS = {'exe', 'dll', 'bin'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        flash('Dosya seçilmedi')
        return redirect(request.url)
    
    file = request.files['file']
    if file.filename == '':
        flash('Dosya seçilmedi')
        return redirect(request.url)
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        # Analiz başlat
        generator = ReportGenerator(file_path)
        results = generator.generate_reports('reports')
        
        if results['html_path']:
            return send_file(results['html_path'], as_attachment=True)
        else:
            flash('Analiz sırasında hata oluştu')
            return redirect(url_for('index'))
    else:
        flash('Geçersiz dosya formatı. Sadece .exe, .dll, .bin dosyaları kabul edilir.')
        return redirect(url_for('index'))

@app.route('/api/analyze', methods=['POST'])
def api_analyze():
    """REST API endpoint for analysis"""
    if 'file' not in request.files:
        return jsonify({'error': 'Dosya bulunamadı'}), 400
    
    file = request.files['file']
    if not allowed_file(file.filename):
        return jsonify({'error': 'Geçersiz dosya formatı'}), 400
    
    # Geçici dosya oluştur
    with tempfile.NamedTemporaryFile(delete=False, suffix='.exe') as tmp_file:
        file.save(tmp_file.name)
        tmp_path = tmp_file.name
    
    try:
        # Analiz yap
        generator = ReportGenerator(tmp_path)
        generator.run_all_analysis()
        
        # JSON data döndür
        return jsonify({
            'success': True,
            'data': generator.analysis_data
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
    finally:
        # Geçici dosyayı sil
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)

@app.route('/interactive')
def interactive_analyzer():
    """Interactive analyzer sayfası"""
    return render_template('interactive.html')

@app.route('/api/disassemble', methods=['POST'])
def api_disassemble():
    """Disassembly API endpoint"""
    if 'file' not in request.files:
        return jsonify({'error': 'Dosya bulunamadı'}), 400
    
    file = request.files['file']
    if not allowed_file(file.filename):
        return jsonify({'error': 'Geçersiz dosya formatı'}), 400
    
    # Geçici dosya oluştur
    with tempfile.NamedTemporaryFile(delete=False, suffix='.exe') as tmp_file:
        file.save(tmp_file.name)
        tmp_path = tmp_file.name
    
    try:
        from tools.ida_like_analyzer import IDALikeAnalyzer
        
        analyzer = IDALikeAnalyzer(tmp_path)
        if analyzer.analyze():
            data = analyzer.generate_idb_like_data()
            return jsonify({
                'success': True,
                'data': data
            })
        else:
            return jsonify({'error': 'Analiz başarısız'}), 500
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
    finally:
        # Geçici dosyayı sil
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)

@app.route('/api/hex_view', methods=['POST'])
def api_hex_view():
    """Hex viewer API endpoint"""
    if 'file' not in request.files:
        return jsonify({'error': 'Dosya bulunamadı'}), 400
    
    file = request.files['file']
    if not allowed_file(file.filename):
        return jsonify({'error': 'Geçersiz dosya formatı'}), 400
    
    # Parameters
    offset = int(request.form.get('offset', 0))
    size = int(request.form.get('size', 512))
    
    # Geçici dosya oluştur
    with tempfile.NamedTemporaryFile(delete=False, suffix='.exe') as tmp_file:
        file.save(tmp_file.name)
        tmp_path = tmp_file.name
    
    try:
        from tools.hex_viewer import InteractiveHexViewer
        
        viewer = InteractiveHexViewer(tmp_path)
        if viewer.load_file():
            hex_lines = []
            
            end_offset = min(offset + size, viewer.file_size)
            for line_offset in range(offset, end_offset, viewer.bytes_per_line):
                hex_line = viewer.format_hex_line(line_offset)
                hex_lines.append({
                    'offset': line_offset,
                    'data': hex_line
                })
            
            return jsonify({
                'success': True,
                'hex_lines': hex_lines,
                'file_size': viewer.file_size,
                'offset': offset,
                'size': len(hex_lines) * viewer.bytes_per_line
            })
        else:
            return jsonify({'error': 'Dosya yüklenemedi'}), 500
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
    finally:
        # Geçici dosyayı sil
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)

# HTML templates oluştur
def create_templates():
    templates_dir = 'templates'
    os.makedirs(templates_dir, exist_ok=True)
    
    # Base template
    base_template = '''<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% block title %}RE Analysis Tool{% endblock %}</title>
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
        </div>
    </nav>
    
    <div class="container mt-4">
        {% with messages = get_flashed_messages() %}
            {% if messages %}
                {% for message in messages %}
                    <div class="alert alert-warning alert-dismissible fade show" role="alert">
                        {{ message }}
                        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                    </div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        
        {% block content %}{% endblock %}
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    {% block scripts %}{% endblock %}
</body>
</html>'''
    
    # Index template
    index_template = '''{% extends "base.html" %}

{% block title %}Reverse Engineering Analysis Tool{% endblock %}

{% block content %}
<div class="row">
    <div class="col-md-8 mx-auto">
        <div class="card">
            <div class="card-header">
                <h3><i class="fas fa-upload"></i> Dosya Yükle ve Analiz Et</h3>
            </div>
            <div class="card-body">
                <form method="POST" action="/upload" enctype="multipart/form-data">
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
                        </ul>
                    </div>
                    <div class="col-md-6">
                        <ul class="list-group list-group-flush">
                            <li class="list-group-item"><i class="fas fa-check text-success"></i> Packer Detection</li>
                            <li class="list-group-item"><i class="fas fa-check text-success"></i> YARA Rules</li>
                            <li class="list-group-item"><i class="fas fa-check text-success"></i> String Extraction</li>
                            <li class="list-group-item"><i class="fas fa-check text-success"></i> HTML/JSON Report</li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>
{% endblock %}

{% block scripts %}
<script>
document.getElementById('fileInput').addEventListener('change', function(e) {
    const file = e.target.files[0];
    if (file) {
        document.getElementById('fileName').textContent = file.name;
        document.getElementById('fileInfo').style.display = 'block';
        document.getElementById('analyzeBtn').disabled = false;
    }
});

// Drag and drop functionality
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
{% endblock %}'''
    
    # Interactive template
    interactive_template = '''{% extends "base.html" %}

{% block title %}Interactive Analyzer{% endblock %}

{% block content %}
<div class="row">
    <div class="col-md-12">
        <div class="card">
            <div class="card-header">
                <h3><i class="fas fa-code"></i> Interactive Binary Analyzer</h3>
                <div class="btn-group" role="group">
                    <button type="button" class="btn btn-outline-primary" onclick="showTab('disassembly')">
                        <i class="fas fa-microchip"></i> Disassembly
                    </button>
                    <button type="button" class="btn btn-outline-primary" onclick="showTab('hexview')">
                        <i class="fas fa-table"></i> Hex View
                    </button>
                    <button type="button" class="btn btn-outline-primary" onclick="showTab('functions')">
                        <i class="fas fa-sitemap"></i> Functions
                    </button>
                    <button type="button" class="btn btn-outline-primary" onclick="showTab('xrefs')">
                        <i class="fas fa-link"></i> Cross-Refs
                    </button>
                </div>
            </div>
            <div class="card-body">
                <!-- File Upload -->
                <div class="mb-3">
                    <input type="file" class="form-control" id="binaryFile" accept=".exe,.dll,.bin">
                    <small class="form-text text-muted">Select a binary file to analyze</small>
                </div>
                
                <!-- Analysis Tabs -->
                <div id="analysisContainer" style="display: none;">
                    <!-- Disassembly Tab -->
                    <div id="disassemblyTab" class="analysis-tab">
                        <div class="row">
                            <div class="col-md-8">
                                <div class="card">
                                    <div class="card-header">
                                        <h5>Disassembly View</h5>
                                        <div class="input-group input-group-sm">
                                            <span class="input-group-text">Go to:</span>
                                            <input type="text" class="form-control" id="gotoAddress" placeholder="0x401000">
                                            <button class="btn btn-outline-secondary" onclick="gotoAddress()">Go</button>
                                        </div>
                                    </div>
                                    <div class="card-body">
                                        <div id="disassemblyContent" class="code-view"></div>
                                    </div>
                                </div>
                            </div>
                            <div class="col-md-4">
                                <div class="card">
                                    <div class="card-header">
                                        <h5>Functions</h5>
                                    </div>
                                    <div class="card-body">
                                        <div id="functionsList" class="function-list"></div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <!-- Hex View Tab -->
                    <div id="hexviewTab" class="analysis-tab" style="display: none;">
                        <div class="card">
                            <div class="card-header">
                                <h5>Hex View</h5>
                                <div class="row">
                                    <div class="col-md-4">
                                        <div class="input-group input-group-sm">
                                            <span class="input-group-text">Offset:</span>
                                            <input type="text" class="form-control" id="hexOffset" value="0" placeholder="0">
                                            <button class="btn btn-outline-secondary" onclick="updateHexView()">Go</button>
                                        </div>
                                    </div>
                                    <div class="col-md-4">
                                        <div class="input-group input-group-sm">
                                            <span class="input-group-text">Size:</span>
                                            <input type="text" class="form-control" id="hexSize" value="512" placeholder="512">
                                        </div>
                                    </div>
                                </div>
                            </div>
                            <div class="card-body">
                                <div id="hexContent" class="hex-view"></div>
                            </div>
                        </div>
                    </div>
                    
                    <!-- Functions Tab -->
                    <div id="functionsTab" class="analysis-tab" style="display: none;">
                        <div class="card">
                            <div class="card-header">
                                <h5>Function Analysis</h5>
                            </div>
                            <div class="card-body">
                                <div class="table-responsive">
                                    <table class="table table-sm" id="functionsTable">
                                        <thead>
                                            <tr>
                                                <th>Address</th>
                                                <th>Name</th>
                                                <th>Size</th>
                                                <th>Instructions</th>
                                                <th>Complexity</th>
                                            </tr>
                                        </thead>
                                        <tbody id="functionsTableBody">
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <!-- Cross-References Tab -->
                    <div id="xrefsTab" class="analysis-tab" style="display: none;">
                        <div class="card">
                            <div class="card-header">
                                <h5>Cross-References</h5>
                            </div>
                            <div class="card-body">
                                <div id="xrefsContent">
                                    <p>Select an address from disassembly to view cross-references.</p>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <!-- Loading Indicator -->
                <div id="loadingIndicator" style="display: none;">
                    <div class="text-center">
                        <div class="spinner-border" role="status">
                            <span class="visually-hidden">Loading...</span>
                        </div>
                        <p class="mt-2">Analyzing binary...</p>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

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

.function-list {
    max-height: 500px;
    overflow-y: auto;
}

.function-item {
    padding: 5px;
    border-bottom: 1px solid #eee;
    cursor: pointer;
}

.function-item:hover {
    background-color: #f5f5f5;
}

.instruction-line {
    margin: 2px 0;
    padding: 2px;
}

.instruction-line:hover {
    background-color: rgba(255, 255, 255, 0.1);
}

.address {
    color: #569cd6;
}

.mnemonic {
    color: #4ec9b0;
    font-weight: bold;
}

.operand {
    color: #ce9178;
}

.hex-address {
    color: #569cd6;
}

.hex-bytes {
    color: #b5cea8;
}

.hex-ascii {
    color: #ce9178;
}
</style>
{% endblock %}

{% block scripts %}
<script>
let currentAnalysisData = null;
let currentFile = null;

document.getElementById('binaryFile').addEventListener('change', function(e) {
    const file = e.target.files[0];
    if (file) {
        currentFile = file;
        analyzeFile(file);
    }
});

function showTab(tabName) {
    // Hide all tabs
    const tabs = document.querySelectorAll('.analysis-tab');
    tabs.forEach(tab => tab.style.display = 'none');
    
    // Show selected tab
    document.getElementById(tabName + 'Tab').style.display = 'block';
    
    // Update active button
    const buttons = document.querySelectorAll('.btn-group .btn');
    buttons.forEach(btn => btn.classList.remove('active'));
    event.target.classList.add('active');
}

function analyzeFile(file) {
    document.getElementById('loadingIndicator').style.display = 'block';
    document.getElementById('analysisContainer').style.display = 'none';
    
    const formData = new FormData();
    formData.append('file', file);
    
    fetch('/api/disassemble', {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        document.getElementById('loadingIndicator').style.display = 'none';
        
        if (data.success) {
            currentAnalysisData = data.data;
            document.getElementById('analysisContainer').style.display = 'block';
            
            // Show disassembly by default
            showTab('disassembly');
            updateDisassemblyView();
            updateFunctionsList();
        } else {
            alert('Analysis failed: ' + data.error);
        }
    })
    .catch(error => {
        document.getElementById('loadingIndicator').style.display = 'none';
        alert('Error: ' + error.message);
    });
}

function updateDisassemblyView() {
    if (!currentAnalysisData || !currentAnalysisData.functions) {
        return;
    }
    
    const content = document.getElementById('disassemblyContent');
    let html = '';
    
    // Entry point function'ını göster
    const entryPoint = currentAnalysisData.pe_info.entry_point;
    const functions = currentAnalysisData.functions;
    
    for (const [address, func] of Object.entries(functions)) {
        html += `<div class="function-header">
            <strong>Function: ${func.name || address}</strong> 
            <span class="text-muted">(${address})</span>
        </div>`;
        
        if (func.instructions) {
            func.instructions.forEach(inst => {
                html += `<div class="instruction-line">
                    <span class="address">${inst.address.toString(16).padStart(8, '0')}:</span>
                    <span class="hex-bytes">${inst.bytes}</span>
                    <span class="mnemonic">${inst.mnemonic}</span>
                    <span class="operand">${inst.op_str || ''}</span>
                </div>`;
            });
        }
        
        html += '<br>';
        
        // İlk birkaç function'ı göster
        if (Object.keys(functions).indexOf(address) > 5) break;
    }
    
    content.innerHTML = html;
}

function updateFunctionsList() {
    if (!currentAnalysisData || !currentAnalysisData.functions) {
        return;
    }
    
    const list = document.getElementById('functionsList');
    let html = '';
    
    for (const [address, func] of Object.entries(currentAnalysisData.functions)) {
        html += `<div class="function-item" onclick="gotoFunction('${address}')">
            <strong>${func.name || 'sub_' + address}</strong><br>
            <small class="text-muted">${address}</small>
        </div>`;
    }
    
    list.innerHTML = html;
}

function gotoFunction(address) {
    // Function'a git
    document.getElementById('gotoAddress').value = address;
    gotoAddress();
}

function gotoAddress() {
    const address = document.getElementById('gotoAddress').value;
    // Address'e scroll et (basit implementation)
    const elements = document.querySelectorAll('.address');
    for (const elem of elements) {
        if (elem.textContent.includes(address.replace('0x', ''))) {
            elem.scrollIntoView({ behavior: 'smooth' });
            elem.parentElement.style.backgroundColor = 'rgba(255, 255, 0, 0.3)';
            setTimeout(() => {
                elem.parentElement.style.backgroundColor = '';
            }, 2000);
            break;
        }
    }
}

function updateHexView() {
    if (!currentFile) {
        return;
    }
    
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
            const content = document.getElementById('hexContent');
            let html = '';
            
            data.hex_lines.forEach(line => {
                html += line.data + '\\n';
            });
            
            content.textContent = html;
        } else {
            alert('Hex view failed: ' + data.error);
        }
    })
    .catch(error => {
        alert('Error: ' + error.message);
    });
}

// Initialize hex view when tab is shown
document.addEventListener('DOMContentLoaded', function() {
    // Set up tab switching
    const buttons = document.querySelectorAll('.btn-group .btn');
    buttons.forEach((btn, index) => {
        btn.addEventListener('click', function() {
            const tabs = ['disassembly', 'hexview', 'functions', 'xrefs'];
            showTab(tabs[index]);
        });
    });
});
</script>
{% endblock %}'''

    # Template dosyalarını yaz
    with open(os.path.join(templates_dir, 'base.html'), 'w', encoding='utf-8') as f:
        f.write(base_template)
    
    with open(os.path.join(templates_dir, 'index.html'), 'w', encoding='utf-8') as f:
        f.write(index_template)
    
    with open(os.path.join(templates_dir, 'interactive.html'), 'w', encoding='utf-8') as f:
        f.write(interactive_template)

if __name__ == '__main__':
    create_templates()
    print("🌐 Web arayüzü başlatılıyor...")
    print("📍 http://localhost:5000 adresinde erişilebilir")
    print("⚠️  Güvenlik: Sadece güvenilir dosyaları yükleyin!")
    app.run(debug=True, host='0.0.0.0', port=5000)