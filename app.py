from flask import Flask, render_template, request, jsonify
import requests
import base64
import os

app = Flask(__name__)

# Mengambil konfigurasi dari Environment Variables server hosting
# Jika tidak ada (saat berjalan di laptop/XAMPP lokal), gunakan defaultnya
VT_API_KEY = os.getenv('VT_API_KEY', '6a16546d675daf22914fafabf00aa2b3bddbe76c0eb9af19e2c6dd319adf7e83')

# URL Webhook Google Apps Script
SPREADSHEET_WEBHOOK_URL = os.getenv('SPREADSHEET_WEBHOOK_URL', '')

# Fungsi cek URL ke VirusTotal
def check_virustotal(url_to_scan):
    try:
        # Encode URL ke format base64 (syarat VirusTotal)
        url_id = base64.urlsafe_b64encode(url_to_scan.encode()).decode().strip("=")
        api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        
        headers = {"x-apikey": VT_API_KEY}
        response = requests.get(api_url, headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            stats = data['data']['attributes']['last_analysis_stats']
            # Jika ada 1 saja vendor bilang malicious, kita anggap BAHAYA
            if stats['malicious'] > 0 or stats['suspicious'] > 0:
                return "BERBAHAYA"
            else:
                return "AMAN"
        else:
            # Jika URL belum pernah discan VT, anggap 'UNKNOWN' (bisa dihandle sbg warning)
            return "TIDAK DIKENALI (HATI-HATI)"
    except Exception as e:
        print(f"Error API: {e}")
        return "ERROR"

# --- ROUTING WEBSITE ---

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan_api', methods=['POST'])
def scan_api():
    data = request.json
    url_link = data.get('url')
    ip_addr = request.remote_addr # Ambil IP HP pengguna

    print(f"Menerima Scan: {url_link} dari {ip_addr}")

    # 1. Cek Keamanan
    status = check_virustotal(url_link)

    # 2. Simpan ke Google Sheets via Webhook
    if SPREADSHEET_WEBHOOK_URL:
        try:
            payload = {
                "url": url_link,
                "status": status,
                "ip": ip_addr
            }
            # Kirim request POST ke Webhook Google Apps Script
            requests.post(SPREADSHEET_WEBHOOK_URL, json=payload)
            print(f"Berhasil dikirim ke Google Sheets: {url_link}")
        except Exception as e:
            print(f"Error mengirim ke Google Sheets: {e}")
    else:
        print("SPREADSHEET_WEBHOOK_URL belum diseting.")

    # 3. Kirim hasil balik ke HP
    return jsonify({'status': status, 'url': url_link})

if __name__ == '__main__':
    # host='0.0.0.0' artinya bisa diakses perangkat lain di WiFi yang sama
    app.run(debug=True, host='0.0.0.0', port=5000)