import logging
import time
import json
import re
import sqlite3
import threading
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from flask import Flask, render_template, request, jsonify, send_file
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from scapy.all import *
import warnings
warnings.filterwarnings('ignore')

app = Flask(__name__)

class AdvancedSecurityAnalytics:
    def __init__(self):
        self.setup_database()
        self.suspicious_patterns = self.load_security_patterns()
        self.real_time_alerts = []
        self.attack_signatures = self.load_attack_signatures()
        
    def setup_database(self):
        self.conn = sqlite3.connect('security_analytics.db', check_same_thread=False)
        cursor = self.conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS firewall_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME,
                source_ip TEXT,
                dest_ip TEXT,
                dest_port INTEGER,
                protocol TEXT,
                payload TEXT,
                severity TEXT,
                threat_type TEXT,
                rule_id TEXT,
                packet_size INTEGER,
                user_agent TEXT,
                country TEXT,
                asn TEXT,
                is_malicious BOOLEAN DEFAULT 0
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME,
                event_type TEXT,
                source_ip TEXT,
                description TEXT,
                severity TEXT,
                risk_score INTEGER,
                status TEXT DEFAULT 'OPEN'
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_intelligence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT,
                threat_type TEXT,
                confidence REAL,
                first_seen DATETIME,
                last_seen DATETIME
            )
        ''')
        
        self.conn.commit()

    def load_security_patterns(self):
        return {
            'sql_injection': [
                r'union\s+select', r'select.*from', r'insert\s+into', 
                r'update.*set', r'drop\s+table', r'or\s+1=1', r';\s*--',
                r'exec\(', r'xp_cmdshell', r'load_file'
            ],
            'xss': [
                r'<script>', r'javascript:', r'onload=', r'onerror=',
                r'onmouseover=', r'alert\(', r'document\.cookie',
                r'<iframe>', r'<img.*src=.*onerror', r'eval\('
            ],
            'path_traversal': [
                r'\.\./', r'\.\.\\', r'etc/passwd', r'win\.ini',
                r'boot\.ini', r'\.\.%2f', r'\.\.%5c', r'proc/self',
                r'\.\.%00'
            ],
            'command_injection': [
                r';.*ls', r';.*cat', r';.*dir', r';.*rm', 
                r'\|\s*sh', r'\|\s*bash', r'`.*`', r'\$\(.*\)',
                r'&&.*kill', r'nc\s+-lvp', r'wget\s+http'
            ],
            'bruteforce': [
                r'failed.*password', r'authentication failed',
                r'incorrect password', r'login failed'
            ],
            'buffer_overflow': [
                r'AAAAAAA', r'\%x\%x\%x', r'\%n\%n\%n',
                r'\x90\x90\x90', r'shellcode', r'bufsiz'
            ],
            'csrf': [
                r'csrf_token', r'anti-csrf', r'_token',
                r'authenticity_token'
            ],
            'lfi': [
                r'include=', r'require=', r'page=', r'file=',
                r'document=', r'template=', r'load='
            ],
            'rfi': [
                r'http://', r'https://', r'ftp://', r'php://',
                r'data://', r'expect://'
            ],
            'xxe': [
                r'<!ENTITY', r'<!DOCTYPE', r'SYSTEM', r'PUBLIC',
                r'%xxe;'
            ]
        }

    def load_attack_signatures(self):
        return {
            'nmap_scan': [r'nmap', r'nessus', r'metasploit'],
            'sqlmap': [r'sqlmap', r'--batch', r'--level'],
            'botnet': [r'zeus', r'spyeye', r'citadel', r'darkcomet'],
            'exploit_kits': [r'blackhole', r'neutrino', r'angler'],
            'web_shells': [r'c99', r'r57', r'wso', r'b374k']
        }

    def analyze_log_file(self, file_path):
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
                logs = file.readlines()
            
            analysis_results = {
                'total_logs': len(logs),
                'threats_detected': 0,
                'suspicious_ips': set(),
                'security_events': [],
                'risk_score': 0
            }
            
            for log_line in logs:
                threats = self.analyze_single_log(log_line)
                if threats:
                    analysis_results['threats_detected'] += len(threats)
                    analysis_results['security_events'].extend(threats)
                    
                    for threat in threats:
                        analysis_results['suspicious_ips'].add(threat.get('source_ip', 'Unknown'))
                        analysis_results['risk_score'] += self.calculate_risk_score(threat['threat_type'])
            
            analysis_results['suspicious_ips'] = list(analysis_results['suspicious_ips'])
            return analysis_results
            
        except Exception as e:
            return {'error': str(e)}

    def analyze_single_log(self, log_line):
        detected_threats = []
        
        # Log formatına göre parse etme
        log_data = self.parse_log_format(log_line)
        
        # OWASP Top 10 kontrolleri
        for threat_type, patterns in self.suspicious_patterns.items():
            for pattern in patterns:
                if re.search(pattern, log_line, re.IGNORECASE):
                    threat_info = {
                        'timestamp': datetime.now().isoformat(),
                        'threat_type': threat_type.upper(),
                        'source_ip': log_data.get('source_ip', 'Unknown'),
                        'log_snippet': log_line[:200],
                        'pattern_matched': pattern,
                        'severity': self.get_threat_severity(threat_type)
                    }
                    detected_threats.append(threat_info)
                    
                    # Veritabanına kaydet
                    self.save_security_event(threat_info)
                    break
        
        # Rate limiting analizi
        rate_limit_threat = self.analyze_rate_limiting(log_data)
        if rate_limit_threat:
            detected_threats.append(rate_limit_threat)
        
        # Geographic anomaly
        geo_threat = self.analyze_geographic_anomaly(log_data)
        if geo_threat:
            detected_threats.append(geo_threat)
            
        return detected_threats

    def parse_log_format(self, log_line):
        # Apache/Nginx log formatını parse et
        apache_pattern = r'(\d+\.\d+\.\d+\.\d+) - - \[(.*?)\] "(.*?)" (\d+) (\d+) "(.*?)" "(.*?)"'
        match = re.match(apache_pattern, log_line)
        
        if match:
            return {
                'source_ip': match.group(1),
                'timestamp': match.group(2),
                'request': match.group(3),
                'status_code': match.group(4),
                'response_size': match.group(5),
                'referer': match.group(6),
                'user_agent': match.group(7)
            }
        
        # Basit IP bazlı parse
        ip_match = re.findall(r'\d+\.\d+\.\d+\.\d+', log_line)
        return {
            'source_ip': ip_match[0] if ip_match else 'Unknown',
            'raw_log': log_line
        }

    def analyze_rate_limiting(self, log_data):
        source_ip = log_data.get('source_ip')
        if source_ip and source_ip != 'Unknown':
            cursor = self.conn.cursor()
            
            # Son 1 dakikadaki istek sayısını kontrol et
            one_min_ago = (datetime.now() - timedelta(minutes=1)).isoformat()
            cursor.execute('''
                SELECT COUNT(*) FROM firewall_logs 
                WHERE source_ip = ? AND timestamp > ?
            ''', (source_ip, one_min_ago))
            
            request_count = cursor.fetchone()[0]
            
            if request_count > 100:  # 100 request/minute threshold
                return {
                    'timestamp': datetime.now().isoformat(),
                    'threat_type': 'RATE_LIMIT_EXCEEDED',
                    'source_ip': source_ip,
                    'description': f'High request rate detected: {request_count} requests/min',
                    'severity': 'HIGH'
                }
        return None

    def analyze_geographic_anomaly(self, log_data):
        # Basit coğrafi anomali tespiti (gerçek uygulamada IP geolocation API kullan)
        source_ip = log_data.get('source_ip')
        if source_ip:
            suspicious_countries = ['CN', 'RU', 'KP', 'IR']  # Örnek şüpheli ülkeler
            
            # Burada gerçek bir geolocation servisi entegre edilebilir
            # Şimdilik IP range'lerine göre basit kontrol
            if source_ip.startswith(('192.168.', '10.', '172.16.')):
                country = 'LAN'
            else:
                country = 'EXTERNAL'
                
            if country in suspicious_countries:
                return {
                    'timestamp': datetime.now().isoformat(),
                    'threat_type': 'SUSPICIOUS_GEO_LOCATION',
                    'source_ip': source_ip,
                    'description': f'Connection from suspicious location: {country}',
                    'severity': 'MEDIUM'
                }
        return None

    def get_threat_severity(self, threat_type):
        severity_map = {
            'sql_injection': 'CRITICAL',
            'xss': 'HIGH',
            'command_injection': 'CRITICAL',
            'path_traversal': 'HIGH',
            'bruteforce': 'MEDIUM',
            'buffer_overflow': 'CRITICAL',
            'csrf': 'MEDIUM',
            'lfi': 'HIGH',
            'rfi': 'CRITICAL',
            'xxe': 'HIGH'
        }
        return severity_map.get(threat_type, 'LOW')

    def calculate_risk_score(self, threat_type):
        risk_scores = {
            'CRITICAL': 10,
            'HIGH': 7,
            'MEDIUM': 4,
            'LOW': 1
        }
        severity = self.get_threat_severity(threat_type.lower())
        return risk_scores.get(severity, 1)

    def save_security_event(self, threat_info):
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT INTO security_events 
            (timestamp, event_type, source_ip, description, severity, risk_score)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            threat_info['timestamp'],
            threat_info['threat_type'],
            threat_info['source_ip'],
            threat_info.get('description', threat_info['log_snippet']),
            threat_info['severity'],
            self.calculate_risk_score(threat_info['threat_type'])
        ))
        self.conn.commit()

    def get_security_dashboard(self):
        cursor = self.conn.cursor()
        
        # Toplam event sayıları
        cursor.execute('''
            SELECT severity, COUNT(*) FROM security_events 
            WHERE timestamp > datetime('now', '-24 hours')
            GROUP BY severity
        ''')
        severity_stats = dict(cursor.fetchall())
        
        # En çok saldırı yapan IP'ler
        cursor.execute('''
            SELECT source_ip, COUNT(*) as attack_count 
            FROM security_events 
            WHERE timestamp > datetime('now', '-24 hours')
            GROUP BY source_ip 
            ORDER BY attack_count DESC 
            LIMIT 10
        ''')
        top_attackers = cursor.fetchall()
        
        # En yaygın saldırı türleri
        cursor.execute('''
            SELECT event_type, COUNT(*) as count 
            FROM security_events 
            WHERE timestamp > datetime('now', '-24 hours')
            GROUP BY event_type 
            ORDER BY count DESC 
            LIMIT 10
        ''')
        attack_types = cursor.fetchall()
        
        return {
            'severity_stats': severity_stats,
            'top_attackers': top_attackers,
            'attack_types': attack_types,
            'total_alerts_24h': sum(severity_stats.values())
        }

class RealTimeFirewall:
    def __init__(self, analytics_engine):
        self.analytics = analytics_engine
        self.blocked_ips = set()
        self.connection_rates = defaultdict(list)
        
    def packet_handler(self, packet):
        if packet.haslayer(IP):
            ip_src = packet[IP].src
            
            # Bloklanmış IP kontrolü
            if ip_src in self.blocked_ips:
                return
                
            # Rate limiting kontrolü
            if not self.check_rate_limit(ip_src):
                self.blocked_ips.add(ip_src)
                self.analytics.save_security_event({
                    'timestamp': datetime.now().isoformat(),
                    'threat_type': 'AUTO_BLOCKED',
                    'source_ip': ip_src,
                    'description': 'Auto-blocked due to rate limiting',
                    'severity': 'HIGH'
                })
                return
            
            # Paket verisini analiz et
            if packet.haslayer(Raw):
                payload = packet[Raw].load.decode('utf-8', errors='ignore')
                threats = self.analytics.analyze_single_log(f"{ip_src} - {payload}")
                
                if threats:
                    for threat in threats:
                        print(f"🚨 Real-time threat detected: {threat}")

    def check_rate_limit(self, ip):
        now = time.time()
        self.connection_rates[ip].append(now)
        
        # 10 saniyelik pencere
        window_start = now - 10
        self.connection_rates[ip] = [t for t in self.connection_rates[ip] if t > window_start]
        
        return len(self.connection_rates[ip]) <= 50  # 50 request/10 seconds

# Flask Routes
security_analytics = AdvancedSecurityAnalytics()
firewall = RealTimeFirewall(security_analytics)

@app.route('/')
def dashboard():
    dashboard_data = security_analytics.get_security_dashboard()
    return render_template('dashboard.html', **dashboard_data)

@app.route('/upload', methods=['POST'])
def upload_log():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    file_path = f"uploads/{file.filename}"
    file.save(file_path)
    
    analysis_results = security_analytics.analyze_log_file(file_path)
    return jsonify(analysis_results)

@app.route('/alerts')
def get_alerts():
    cursor = security_analytics.conn.cursor()
    cursor.execute('''
        SELECT * FROM security_events 
        ORDER BY timestamp DESC 
        LIMIT 100
    ''')
    alerts = cursor.fetchall()
    
    return jsonify([
        {
            'id': alert[0],
            'timestamp': alert[1],
            'event_type': alert[2],
            'source_ip': alert[3],
            'description': alert[4],
            'severity': alert[5],
            'risk_score': alert[6],
            'status': alert[7]
        } for alert in alerts
    ])

@app.route('/stats')
def get_statistics():
    cursor = security_analytics.conn.cursor()
    
    # 24 saatlik zaman serisi
    cursor.execute('''
        SELECT strftime('%H', timestamp) as hour, 
               COUNT(*) as count 
        FROM security_events 
        WHERE timestamp > datetime('now', '-24 hours')
        GROUP BY hour 
        ORDER BY hour
    ''')
    hourly_data = cursor.fetchall()
    
    return jsonify({
        'hourly_attacks': hourly_data,
        'total_blocked_ips': len(firewall.blocked_ips)
    })

@app.route('/start_firewall')
def start_firewall():
    def start_sniffing():
        sniff(prn=firewall.packet_handler, store=0)
    
    thread = threading.Thread(target=start_sniffing)
    thread.daemon = True
    thread.start()
    
    return jsonify({'status': 'Firewall started'})

@app.route('/block_ip', methods=['POST'])
def block_ip():
    ip = request.json.get('ip')
    if ip:
        firewall.blocked_ips.add(ip)
        return jsonify({'status': f'IP {ip} blocked'})
    return jsonify({'error': 'No IP provided'}), 400

if __name__ == '__main__':
    import os
    os.makedirs('uploads', exist_ok=True)
    
    app.run(host='0.0.0.0', port=5000, debug=True)
