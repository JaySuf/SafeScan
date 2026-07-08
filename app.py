from flask import Flask, render_template, request, jsonify
import requests
import base64
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

# Mengambil konfigurasi dari Environment Variables server hosting
# Jika tidak ada (saat berjalan di laptop/XAMPP lokal), gunakan defaultnya
VT_API_KEY = os.getenv('VT_API_KEY', '6a16546d675daf22914fafabf00aa2b3bddbe76c0eb9af19e2c6dd319adf7e83')


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
    if not url_link:
        return jsonify({'error': 'URL tidak valid'}), 400
        
    # Ambil IP HP pengguna (Mendukung proxy/Vercel)
    ip_addr = request.headers.get('X-Forwarded-For', request.remote_addr)
    if not ip_addr:
        ip_addr = 'Unknown IP'
    ip_addr = ip_addr.split(',')[0].strip()

    print(f"Menerima Scan: {url_link} dari {ip_addr}")

    # 1. Cek Keamanan
    status = check_virustotal(url_link)



    # 3. Kirim hasil balik ke HP
    return jsonify({'status': status, 'url': url_link})

if __name__ == '__main__':
    # host='0.0.0.0' artinya bisa diakses perangkat lain di WiFi yang sama
    app.run(debug=True, host='0.0.0.0', port=5000)