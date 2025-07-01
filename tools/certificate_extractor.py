#!/usr/bin/env python3
"""
Certificate Extractor and Digital Signature Analyzer
PE dosyalarından sertifika ve imza bilgilerini çıkarma
"""

import sys
import os
import struct
import hashlib
from datetime import datetime
import base64

class CertificateExtractor:
    def __init__(self, file_path, output_dir="extracted/certificates"):
        self.file_path = file_path
        self.output_dir = output_dir
        self.file_data = None
        self.pe_offset = None
        self.certificates = []
        self.signature_info = {}
        
        os.makedirs(output_dir, exist_ok=True)
        
    def load_file(self):
        """Dosyayı yükle"""
        try:
            with open(self.file_path, 'rb') as f:
                self.file_data = f.read()
            return True
        except Exception as e:
            print(f"Dosya yüklenemedi: {e}")
            return False
    
    def parse_pe_structure(self):
        """PE yapısını parse et"""
        if len(self.file_data) < 64:
            return False
            
        if self.file_data[:2] != b'MZ':
            return False
            
        self.pe_offset = struct.unpack('<I', self.file_data[60:64])[0]
        
        if self.file_data[self.pe_offset:self.pe_offset+4] != b'PE\x00\x00':
            return False
            
        return True
    
    def get_security_directory(self):
        """Security Directory'yi al"""
        # Optional header'dan Security Directory RVA ve size'ı al
        opt_header_offset = self.pe_offset + 24
        
        # PE32 veya PE32+ kontrol et
        magic = struct.unpack('<H', self.file_data[opt_header_offset:opt_header_offset + 2])[0]
        
        if magic == 0x10b:  # PE32
            security_dir_offset = opt_header_offset + 128
        elif magic == 0x20b:  # PE32+
            security_dir_offset = opt_header_offset + 144
        else:
            return None, None
            
        if security_dir_offset + 8 > len(self.file_data):
            return None, None
            
        security_rva = struct.unpack('<I', self.file_data[security_dir_offset:security_dir_offset + 4])[0]
        security_size = struct.unpack('<I', self.file_data[security_dir_offset + 4:security_dir_offset + 8])[0]
        
        return security_rva, security_size
    
    def parse_pkcs7_certificate(self, cert_data):
        """PKCS#7 sertifika bilgilerini basit parsing"""
        cert_info = {
            'size': len(cert_data),
            'type': 'PKCS#7',
            'sha1': hashlib.sha1(cert_data).hexdigest(),
            'sha256': hashlib.sha256(cert_data).hexdigest(),
            'subjects': [],
            'issuers': [],
            'serial_numbers': [],
            'validity': {}
        }
        
        # Basit string arama ile sertifika bilgileri çıkar
        try:
            cert_str = cert_data.decode('ascii', errors='ignore')
            
            # Common Name (CN) ara
            cn_matches = []
            for pattern in [r'CN=([^,\r\n]+)', r'commonName=([^,\r\n]+)']:
                import re
                matches = re.findall(pattern, cert_str, re.IGNORECASE)
                cn_matches.extend(matches)
            
            cert_info['common_names'] = list(set(cn_matches))
            
            # Organization (O) ara
            org_matches = []
            for pattern in [r'O=([^,\r\n]+)', r'organizationName=([^,\r\n]+)']:
                matches = re.findall(pattern, cert_str, re.IGNORECASE)
                org_matches.extend(matches)
            
            cert_info['organizations'] = list(set(org_matches))
            
            # Email ara
            email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
            emails = re.findall(email_pattern, cert_str)
            cert_info['emails'] = emails
            
        except Exception as e:
            cert_info['parse_error'] = str(e)
        
        return cert_info
    
    def extract_certificates(self):
        """Sertifikaları çıkar"""
        security_rva, security_size = self.get_security_directory()
        
        if not security_rva or not security_size:
            return []
            
        # Security directory dosya offset'ine çevir (RVA değil, file offset)
        cert_table_offset = security_rva
        
        if cert_table_offset + security_size > len(self.file_data):
            return []
        
        certificates = []
        offset = cert_table_offset
        
        while offset < cert_table_offset + security_size:
            if offset + 8 > len(self.file_data):
                break
                
            # Certificate entry header
            length = struct.unpack('<I', self.file_data[offset:offset + 4])[0]
            revision = struct.unpack('<H', self.file_data[offset + 4:offset + 6])[0]
            cert_type = struct.unpack('<H', self.file_data[offset + 6:offset + 8])[0]
            
            if length < 8 or offset + length > len(self.file_data):
                break
                
            # Certificate data
            cert_data = self.file_data[offset + 8:offset + length]
            
            cert_info = {
                'offset': offset,
                'length': length,
                'revision': revision,
                'type': cert_type,
                'type_name': self.get_cert_type_name(cert_type),
                'data': cert_data
            }
            
            # PKCS#7 ise parse et
            if cert_type == 0x0002:  # WIN_CERT_TYPE_PKCS_SIGNED_DATA
                pkcs7_info = self.parse_pkcs7_certificate(cert_data)
                cert_info.update(pkcs7_info)
            
            certificates.append(cert_info)
            
            # Next certificate (align to 8-byte boundary)
            offset += (length + 7) & ~7
        
        return certificates
    
    def get_cert_type_name(self, cert_type):
        """Certificate type'ını string'e çevir"""
        types = {
            0x0001: "WIN_CERT_TYPE_X509",
            0x0002: "WIN_CERT_TYPE_PKCS_SIGNED_DATA",
            0x0003: "WIN_CERT_TYPE_RESERVED_1",
            0x0004: "WIN_CERT_TYPE_TS_STACK_SIGNED"
        }
        return types.get(cert_type, f"UNKNOWN_TYPE_{cert_type}")
    
    def validate_signature(self):
        """İmzayı doğrula (basit kontrol)"""
        validation = {
            'signed': len(self.certificates) > 0,
            'certificate_count': len(self.certificates),
            'trusted': False,  # Gerçek doğrulama için CA chain kontrolü gerekli
            'issues': []
        }
        
        if not validation['signed']:
            validation['issues'].append("Dosya dijital olarak imzalanmamış")
            return validation
        
        # Sertifika zinciri kontrolleri
        for i, cert in enumerate(self.certificates):
            if cert.get('parse_error'):
                validation['issues'].append(f"Sertifika {i+1} parse edilemedi: {cert['parse_error']}")
            
            if not cert.get('common_names'):
                validation['issues'].append(f"Sertifika {i+1} Common Name bilgisi eksik")
        
        return validation
    
    def save_certificates(self, file_base):
        """Sertifikaları dosyaya kaydet"""
        saved_files = []
        
        for i, cert in enumerate(self.certificates):
            # Binary sertifika dosyası
            cert_file = os.path.join(self.output_dir, f"{file_base}_cert_{i+1}.der")
            with open(cert_file, 'wb') as f:
                f.write(cert['data'])
            saved_files.append(cert_file)
            
            # Base64 encoded sertifika
            b64_file = os.path.join(self.output_dir, f"{file_base}_cert_{i+1}.pem")
            with open(b64_file, 'w') as f:
                f.write("-----BEGIN CERTIFICATE-----\n")
                b64_data = base64.b64encode(cert['data']).decode('ascii')
                for j in range(0, len(b64_data), 64):
                    f.write(b64_data[j:j+64] + "\n")
                f.write("-----END CERTIFICATE-----\n")
            saved_files.append(b64_file)
            
            # Sertifika bilgileri
            info_file = os.path.join(self.output_dir, f"{file_base}_cert_{i+1}_info.txt")
            with open(info_file, 'w') as f:
                f.write(f"Certificate #{i+1} Information\n")
                f.write("=" * 40 + "\n\n")
                f.write(f"Type: {cert['type_name']} (0x{cert['type']:04x})\n")
                f.write(f"Revision: {cert['revision']}\n")
                f.write(f"Length: {cert['length']} bytes\n")
                f.write(f"File Offset: 0x{cert['offset']:08x}\n")
                f.write(f"SHA1: {cert.get('sha1', 'N/A')}\n")
                f.write(f"SHA256: {cert.get('sha256', 'N/A')}\n\n")
                
                if cert.get('common_names'):
                    f.write("Common Names:\n")
                    for cn in cert['common_names']:
                        f.write(f"  - {cn}\n")
                    f.write("\n")
                
                if cert.get('organizations'):
                    f.write("Organizations:\n")
                    for org in cert['organizations']:
                        f.write(f"  - {org}\n")
                    f.write("\n")
                
                if cert.get('emails'):
                    f.write("Email Addresses:\n")
                    for email in cert['emails']:
                        f.write(f"  - {email}\n")
                    f.write("\n")
                
                if cert.get('parse_error'):
                    f.write(f"Parse Error: {cert['parse_error']}\n")
            
            saved_files.append(info_file)
        
        return saved_files
    
    def analyze(self):
        """Ana analiz fonksiyonu"""
        if not self.load_file():
            return False
            
        print(f"🔐 CERTIFICATE ANALYSIS: {os.path.basename(self.file_path)}")
        print("=" * 80)
        
        if not self.parse_pe_structure():
            print("❌ PE yapısı parse edilemedi - dosya analiz edilemiyor")
            # PE değilse bile dosya bilgilerini kaydet
            self.save_non_pe_info()
            return True
            
        # Sertifikaları çıkar
        self.certificates = self.extract_certificates()
        
        if not self.certificates:
            print("❌ Dijital sertifika bulunamadı")
            print("   Bu dosya imzalanmamış veya sertifika hasarlı")
            
            # Boş olsa bile bilgi dosyası oluştur
            file_base = os.path.splitext(os.path.basename(self.file_path))[0]
            info_file = os.path.join(self.output_dir, f"{file_base}_certificate_info.txt")
            with open(info_file, 'w') as f:
                f.write(f"Certificate Analysis: {os.path.basename(self.file_path)}\n")
                f.write("=" * 50 + "\n\n")
                f.write("RESULT: No digital certificates found\n\n")
                f.write("This file is either:\n")
                f.write("- Not digitally signed\n")
                f.write("- Has corrupted certificate data\n")
                f.write("- Uses unsupported certificate format\n\n")
                f.write(f"File Size: {len(self.file_data):,} bytes\n")
                f.write(f"Analysis Date: {os.path.basename(self.file_path)}\n")
            
            print(f"📄 Info file created: {info_file}")
            return True
        
        print(f"✅ {len(self.certificates)} adet sertifika bulundu")
        
        # Her sertifika için bilgileri göster
        for i, cert in enumerate(self.certificates):
            print(f"\n📜 Sertifika #{i+1}")
            print(f"   Type: {cert['type_name']}")
            print(f"   Size: {cert['length']} bytes")
            
            if cert.get('common_names'):
                print(f"   Common Names: {', '.join(cert['common_names'])}")
            
            if cert.get('organizations'):
                print(f"   Organizations: {', '.join(cert['organizations'])}")
            
            if cert.get('emails'):
                print(f"   Emails: {', '.join(cert['emails'])}")
        
        # İmza doğrulama
        validation = self.validate_signature()
        print(f"\n🔍 SIGNATURE VALIDATION")
        print(f"   Signed: {'✅ Yes' if validation['signed'] else '❌ No'}")
        print(f"   Certificate Count: {validation['certificate_count']}")
        print(f"   Trusted: {'✅ Yes' if validation['trusted'] else '❓ Unknown'}")
        
        if validation['issues']:
            print(f"   Issues:")
            for issue in validation['issues']:
                print(f"     ⚠️  {issue}")
        
        # Sertifikaları kaydet
        file_base = os.path.splitext(os.path.basename(self.file_path))[0]
        saved_files = self.save_certificates(file_base)
        
        if saved_files:
            print(f"\n💾 Sertifikalar kaydedildi ({len(saved_files)} dosya):")
            for file_path in saved_files[:5]:  # İlk 5 dosyayı göster
                print(f"   📄 {os.path.basename(file_path)}")
            if len(saved_files) > 5:
                print(f"   ... ve {len(saved_files) - 5} dosya daha")
        
        print(f"\n✅ Sertifika analizi tamamlandı!")
        return True
    
    def save_non_pe_info(self):
        """PE olmayan dosyalar için bilgi kaydet"""
        file_base = os.path.splitext(os.path.basename(self.file_path))[0]
        info_file = os.path.join(self.output_dir, f"{file_base}_analysis_info.txt")
        
        with open(info_file, 'w') as f:
            f.write(f"File Analysis: {os.path.basename(self.file_path)}\n")
            f.write("=" * 50 + "\n\n")
            f.write("RESULT: Not a valid PE file\n\n")
            f.write("This file cannot be analyzed as a Windows executable.\n")
            f.write("Possible file types:\n")
            f.write("- Non-executable file\n")
            f.write("- Corrupted PE file\n")
            f.write("- Different executable format (ELF, Mach-O, etc.)\n\n")
            f.write(f"File Size: {len(self.file_data):,} bytes\n")
            
            # İlk birkaç byte'ı göster
            f.write("\nFile Header (first 32 bytes):\n")
            hex_data = ' '.join(f'{b:02x}' for b in self.file_data[:32])
            f.write(f"  {hex_data}\n")
        
        print(f"📄 Analysis info saved: {info_file}")

def main():
    if len(sys.argv) < 2:
        print("Kullanım: python certificate_extractor.py <exe_dosyasi> [output_dir]")
        sys.exit(1)
    
    file_path = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else "extracted/certificates"
    
    if not os.path.exists(file_path):
        print(f"Dosya bulunamadı: {file_path}")
        sys.exit(1)
    
    extractor = CertificateExtractor(file_path, output_dir)
    extractor.analyze()

if __name__ == "__main__":
    main()