import json
import random
from datetime import datetime, timedelta

# --- AYARLAR ---
OUTPUT_FILE = "collected_threat_data.json"
DATA_COUNT = 1000  # Üretilecek veri sayısı

# Simüle edilecek ülkeler ve ağırlıkları (Siber tehditlerde sık görülen ülkeler)
COUNTRIES = ['CN', 'RU', 'US', 'TR', 'DE', 'BR', 'IN', 'IR', 'KP', 'NL']
WEIGHTS = [0.20, 0.15, 0.15, 0.10, 0.05, 0.05, 0.10, 0.10, 0.05, 0.05]  # Çin ve Rusya ağırlıklı

IOC_TYPES = ['IP_Address', 'URL']


def generate_random_ip():
    return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"


def generate_random_url():
    protocols = ['http', 'https']
    domains = ['example.com', 'test.org', 'malware.net', 'phishing.xyz', 'bank-login-secure.com']
    paths = ['login', 'admin', 'wp-content', 'secure', 'bin', 'update']
    return f"{random.choice(protocols)}://{random.choice(domains)}/{random.choice(paths)}/{random.randint(100, 999)}"


def create_mock_data():
    data_list = []
    print(f"--- {DATA_COUNT} Adet Sentetik Veri Üretiliyor ---")

    for _ in range(DATA_COUNT):
        # Rastgele ülke seç (Ağırlıklı)
        country = random.choices(COUNTRIES, weights=WEIGHTS, k=1)[0]

        # Rastgele tür seç
        ioc_type = random.choice(IOC_TYPES)
        value = generate_random_ip() if ioc_type == 'IP_Address' else generate_random_url()

        # Rastgele güven skoru (0 ile 100 arası)
        # Tehditlerin çoğu düşük riskli olur, bazıları çok yüksek riskli olur.
        if random.random() < 0.1:  # %10 ihtimalle çok yüksek riskli
            confidence = random.uniform(0.8, 1.0)
            report_count = random.randint(50, 500)
        else:
            confidence = random.uniform(0.0, 0.5)
            report_count = random.randint(0, 10)

        # Veri yapısı
        ioc = {
            "ioc_type": ioc_type,
            "value": value,
            "source": "MockGenerator",
            "timestamp": (datetime.now() - timedelta(minutes=random.randint(1, 10000))).isoformat(),
            "confidence_score": confidence,
            "tags": ["simulated_threat"],
            "extra_data": {
                "country": country,
                "report_count": report_count,
                "isp": "Simulated ISP"
            }
        }
        data_list.append(ioc)

    # Dosyaya kaydet
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        json.dump(data_list, f, ensure_ascii=False, indent=4)

    print(f"✅ Başarılı! '{OUTPUT_FILE}' dosyasına {len(data_list)} adet veri kaydedildi.")
    print("Şimdi sırasıyla 'db_uploader.py' ve 'ai_analyzer.py' dosyalarını çalıştırın.")


if __name__ == "__main__":
    create_mock_data()