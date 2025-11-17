import requests
import json
from datetime import datetime
import time

# --- YAPILANDIRMA VE API ANAHTARLARI ---
# Kullanıcı tarafından sağlanan API anahtarları buraya entegre edilmiştir.
ABUSEIPDB_API_KEY = "1890d3080a0b2684da0c9b953733ac0aeef4cda9379d038b9e8231cfd1fc9c4b96647fdae1673feb"
URLSCAN_API_KEY = "0199e7f0-8c02-73b2-b903-d4df0fb995ef"

# Test etmek için kullanılacak Indicators of Compromise (IoC) listesi
TEST_IOCS = {
    "ip": ["104.244.42.129", "185.239.242.112"],
    "url": ["http://testphp.vulnweb.com/", "https://www.google.com/"]
}

OUTPUT_FILE = "collected_threat_data.json"
API_WAIT_TIME = 5  # URLScan.io sonuçları için bekleme süresi (saniye)


# --- ORTAK VERİ MODELİ (NORMALİZASYON ŞEMASI) ---
def create_normalized_ioc(ioc_type, value, source, confidence=None, tags=None, extra_data=None):
    """Farklı kaynaklardan gelen veriyi ortak bir şemaya dönüştürür."""
    return {
        "ioc_type": ioc_type,
        "value": value,
        "source": source,
        "timestamp": datetime.now().isoformat(),
        "confidence_score": confidence if confidence is not None else 0.5,
        "tags": tags if tags is not None else ["osint_scan"],
        "extra_data": extra_data if extra_data is not None else {}
    }


# --- ABUSEIPDB VERİ İŞLEMLERİ ---
def fetch_abuseipdb(ip_address):
    """AbuseIPDB API'dan IP adresi tehdit verisini çeker."""
    url = 'https://api.abuseipdb.com/api/v2/check'
    params = {'ipAddress': ip_address, 'maxAgeInDays': 90, 'verbose': True}
    headers = {'Accept': 'application/json', 'Key': ABUSEIPDB_API_KEY}

    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()  # HTTP hatalarını yakala
        data = response.json().get('data', {})

        if data:
            # Güven puanını 0-1 aralığına normalize et
            confidence = data.get('abuseConfidenceScore', 0) / 100
            tags = ["ip_abuse"]
            if data.get('isWhitelisted'): tags.append("whitelisted")

            # Normalleştirilmiş IOC'yi oluştur
            return create_normalized_ioc(
                ioc_type="IP_Address",
                value=ip_address,
                source="AbuseIPDB",
                confidence=confidence,
                tags=tags,
                extra_data={
                    "report_count": data.get('totalReports', 0),
                    "country": data.get('countryCode'),
                    "isp": data.get('isp')
                }
            )

    except requests.exceptions.HTTPError as e:
        print(f"HATA [AbuseIPDB - {ip_address}]: HTTP Hatası. API Key veya limit kontrolü yapın. Hata: {e}")
    except Exception as e:
        print(f"HATA [AbuseIPDB - {ip_address}]: Genel Hata: {e}")

    return None


# --- URLSCAN.IO VERİ İŞLEMLERİ ---
def submit_urlscan_scan(url):
    """URLScan.io'ya URL analizi isteği gönderir ve sonucu bekler."""
    submit_url = 'https://urlscan.io/api/v1/scan/'
    headers = {'API-Key': URLSCAN_API_KEY, 'Content-Type': 'application/json'}
    data = {"url": url, "public": "on"}

    try:
        # Tarama isteği gönder
        submit_response = requests.post(submit_url, headers=headers, data=json.dumps(data))
        submit_response.raise_for_status()
        submission_data = submit_response.json()
        uuid = submission_data.get('uuid')

        if not uuid:
            print(f"HATA [URLScan.io - {url}]: Tarama başlatılamadı.")
            return None

        print(f"  -> URLScan.io analizi başlatıldı. UUID: {uuid}")

        # Sonuç gelene kadar bekleme döngüsü
        result_url = f"https://urlscan.io/api/v1/result/{uuid}/"
        for i in range(10):
            time.sleep(API_WAIT_TIME)
            result_response = requests.get(result_url, headers=headers)

            if result_response.status_code == 200:
                print(f"  -> Sonuç {i + 1}. denemede alındı.")
                return normalize_urlscan_result(url, result_response.json())

            print(f"  -> {i + 1}. deneme: Sonuç henüz hazır değil. {API_WAIT_TIME} saniye bekleniyor...")

    except requests.exceptions.HTTPError as e:
        print(f"HATA [URLScan.io - {url}]: HTTP Hatası. API Key veya limit kontrolü yapın. Hata: {e}")
    except Exception as e:
        print(f"HATA [URLScan.io - {url}]: Genel Hata: {e}")

    return None


def normalize_urlscan_result(url, result_data):
    """URLScan.io sonuçlarından IOC'leri çıkarır ve normalize eder."""

    verdicts = result_data.get('verdicts', {})
    score = verdicts.get('malicious', {}).get('score', 0)
    confidence = score / 100

    tags = ["url_scan", "url_analysis"]
    if score > 0: tags.append("malicious_detected")

    extracted_iocs = result_data.get('lists', {})

    extra_data = {
        "main_ip": result_data.get('page', {}).get('ip'),
        "country": result_data.get('page', {}).get('country'),
        "page_status": result_data.get('task', {}).get('status'),
        "domains_contacted": extracted_iocs.get('domains', [])
    }

    normalized_url_ioc = create_normalized_ioc(
        ioc_type="URL",
        value=url,
        source="URLScan.io",
        confidence=confidence,
        tags=tags,
        extra_data=extra_data
    )

    # URL IOC'si ve çıkarılan IP'ler birleştirilir (Zenginleştirme)
    all_iocs = [normalized_url_ioc]
    for ip in extracted_iocs.get('ips', []):
        ip_ioc = create_normalized_ioc(
            ioc_type="IP_Address",
            value=ip,
            source="URLScan.io_Extraction",
            confidence=confidence * 0.7,  # Güveni ana URL'den biraz düşük tut
            tags=["ip_extraction", "related_to_url_scan"],
            extra_data={"parent_url": url}
        )
        all_iocs.append(ip_ioc)

    return all_iocs


# --- ANA ÇALIŞTIRMA FONKSİYONU ---
def main_collector():
    """Veri toplama akışını yönetir."""
    collected_iocs = []

    print(f"--- Tehdit Verisi Toplama Başlatıldı ({datetime.now().strftime('%Y-%m-%d %H:%M:%S')}) ---")

    # 1. IP Adreslerini Kontrol Et
    print("\n[AbuseIPDB] IP Adresleri Kontrol Ediliyor...")
    for ip in TEST_IOCS["ip"]:
        print(f" -> İşleniyor: {ip}")
        result = fetch_abuseipdb(ip)
        if result:
            collected_iocs.append(result)

    # 2. URL'leri Kontrol Et
    print("\n[URLScan.io] URL'ler Analiz Ediliyor (İşlem yaklaşık 50 saniye sürebilir)...")
    for url in TEST_IOCS["url"]:
        print(f" -> İşleniyor: {url}")
        results = submit_urlscan_scan(url)
        if results:
            collected_iocs.extend(results)

    # 3. Sonuçları JSON dosyasına kaydet
    if collected_iocs:
        try:
            with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
                json.dump(collected_iocs, f, ensure_ascii=False, indent=4)
            print(
                f"\n✅ BAŞARILI: {len(collected_iocs)} adet normalize edilmiş IOC verisi '{OUTPUT_FILE}' dosyasına kaydedildi.")
            print(f"Bu dosya, projenin bir sonraki aşamasında (Veritabanı) kullanılacaktır.")
        except Exception as e:
            print(f"\n❌ HATA: Dosyaya yazma hatası: {e}")
    else:
        print(
            "\nUYARI: Hiç tehdit verisi toplanamadı. API anahtarlarınızın doğru olduğundan ve günlük limitlerinizi aşmadığınızdan emin olun.")

    print(f"\n--- Toplama Tamamlandı ({datetime.now().strftime('%Y-%m-%d %H:%M:%S')}) ---")


if __name__ == "__main__":
    main_collector()
