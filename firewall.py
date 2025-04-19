
import logging
import time
import smtplib
from email.mime.text import MIMEText
from scapy.all import *
from sklearn.ensemble import IsolationForest
import geocoder
from cryptography.fernet import Fernet
import shutil
import os
from flask import Flask, jsonify
import numpy as np

# Logger Ayarları
logging.basicConfig(filename="firewall_log.log", level=logging.INFO)

# Firewall Konfigürasyonları
ALLOWED_IPS = ["127.0.0.1"]
BLOCKED_PORTS = [80, 443]
HONEYPOT_PORTS = [8080, 9090]
RATE_LIMIT = 10
blocked_ips = {}
connection_count = {}
botnet_ips = {}
critical_ips = ["192.168.1.100"]  # Örnek kritik IP'ler

# Makine Öğrenmesi ile Anomali Tespiti
def ai_anomaly_detection(packet):
    model = IsolationForest(contamination=0.1)
    features = np.array([[packet[IP].src, packet[IP].dst, packet[IP].len, packet[IP].ttl]])  # Trafik özellikleri
    prediction = model.predict(features)
    
    if prediction == -1:
        print(f"[AI Anomaly] IP {packet[IP].src} anomali olarak tespit edildi!")
        log_connection(packet[IP].src, packet.dport, "Blocked (AI Anomaly)")
        return False
    return True

# Deep Packet Inspection (DPI)
def dpi_analysis(packet):
    if packet.haslayer(Raw):
        raw_data = packet[Raw].load.decode(errors="ignore")
        if "malicious_payload" in raw_data:
            print(f"[DPI] Kötü amaçlı trafik tespit edildi, IP: {packet[IP].src}")
            log_connection(packet[IP].src, packet.dport, "Blocked (DPI)")
            return False
    return True

# Web Application Firewall (WAF) - SQLi ve XSS
def detect_web_attacks(packet):
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        raw_data = packet[Raw].load.decode(errors="ignore")
        if "SELECT" in raw_data or "DROP" in raw_data:
            print(f"[SQL Injection] Şüpheli SQL sorgusu tespit edildi, IP: {packet[IP].src}")
            log_connection(packet[IP].src, packet.dport, "Blocked (SQL Injection)")
            return False
        if "<script>" in raw_data:
            print(f"[XSS] Şüpheli XSS saldırısı tespit edildi, IP: {packet[IP].src}")
            log_connection(packet[IP].src, packet.dport, "Blocked (XSS)")
            return False
    return True

# VPN ve Proxy Engelleme
def detect_vpn(packet):
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        if "X-Forwarded-For" in packet[Raw].load.decode(errors="ignore"):
            print(f"[VPN/Proxy] Proxy tespit edildi, IP: {ip_src}")
            log_connection(ip_src, packet.dport, "Blocked (VPN/Proxy)")
            return False
    return True

# DNS Tünelleme Tespiti
def detect_dns_tunneling(packet):
    if packet.haslayer(DNS):
        dns_query = packet[DNS].qd.qname.decode()
        malicious_domains = ["maliciousdomain.com", "exploitdomain.com"]
        if any(domain in dns_query for domain in malicious_domains):
            print(f"[DNS Tunneling] Şüpheli DNS sorgusu tespit edildi: {dns_query}, IP: {packet[IP].src}")
            log_connection(packet[IP].src, packet.dport, "Blocked (DNS Tunneling)")
            return False
    return True

# Anomali Algoritması
def advanced_anomaly_detection(packet):
    if packet.haslayer(TCP) and packet[TCP].flags == "S":
        print(f"[Anomaly Detection] Şüpheli SYN Flood tespit edildi, IP: {packet[IP].src}")
        log_connection(packet[IP].src, packet.dport, "Blocked (Anomaly Detection)")
        return False
    return True

# Kötü Amaçlı Yazılım Tespiti (Antivirüs)
def antivirus_scan(packet):
    if packet.haslayer(Raw):
        raw_data = packet[Raw].load.decode(errors="ignore")
        malware_signatures = ["malware_signature", "trojan_signature"]
        if any(signature in raw_data for signature in malware_signatures):
            print(f"[Antivirus] Kötü amaçlı yazılım tespit edildi, IP: {packet[IP].src}")
            log_connection(packet[IP].src, packet.dport, "Blocked (Antivirus)")
            return False
    return True

# IP Geolokasyonu Tespiti
def is_geo_allowed(ip):
    g = geocoder.ip(ip)
    country = g.country
    allowed_countries = ['US', 'GB', 'DE']
    if country in allowed_countries:
        return True
    print(f"[Geo-blocking] Engellenmiş ülke: {country}, IP: {ip}")
    return False

# Saldırı Alarmı ve Bildirim Sistemi
def send_alert(ip, message):
    from_email = "your_email@example.com"
    to_email = "admin@example.com"
    subject = "Firewall Alert"
    body = f"IP {ip} - {message}"

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = from_email
    msg["To"] = to_email

    try:
        server = smtplib.SMTP("smtp.example.com", 587)
        server.starttls()
        server.login(from_email, "your_password")
        server.sendmail(from_email, to_email, msg.as_string())
        server.quit()
        print("Alert email sent!")
    except Exception as e:
        print(f"Error sending email: {e}")

# Loglama Fonksiyonu
def log_connection(ip, port, status):
    logging.info(f"Time: {time.ctime()}, IP: {ip}, Port: {port}, Status: {status}")

# Firewall Paket Callback
def packet_callback(packet):
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        port = packet.dport if packet.haslayer(TCP) else None

        # Anomali Tespiti
        if not advanced_anomaly_detection(packet):
            return None
        
        # VPN/Proxy Engelleme
        if not detect_vpn(packet):
            return None
        
        # DNS Tünelleme Tespiti
        if not detect_dns_tunneling(packet):
            return None
        
        # Web Saldırıları
        if not detect_web_attacks(packet):
            return None
        
        # Antivirüs Taraması
        if not antivirus_scan(packet):
            return None

        # IP Geolokasyonu Kontrolü
        if not is_geo_allowed(ip_src):
            return None

        # Kötü Amaçlı Yazılım
        if not antivirus_scan(packet):
            return None

        log_connection(ip_src, port, "Allowed")
        print(f"Allowed connection from {ip_src} to port {port}")

# Firewall Başlatma
def start_firewall():
    print("Gelişmiş Firewall çalışıyor...")
    sniff(prn=packet_callback, store=0)

# Firewall'ı başlatıyoruz
if __name__ == "__main__":
    start_firewall()
