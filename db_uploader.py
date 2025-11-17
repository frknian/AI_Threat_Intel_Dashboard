import json
from elasticsearch import Elasticsearch
import pandas as pd
from datetime import datetime
import warnings

# Geliştirme uyarılarını gizle
warnings.filterwarnings('ignore')

# --- YAPILANDIRMA ---
ELASTIC_HOST = "https://localhost:9200"
ELASTIC_USERNAME = "elastic"
# Bu şifre, Kibana/Streamlit'te kullanılan ve sıfırlanan şifrenizdir.
ELASTIC_PASSWORD = "yRFjrY9G-h9a188KWrjE"
INDEX_NAME = "threat_iocs"
INPUT_FILE = "collected_threat_data.json"


def connect_to_elasticsearch():
    """Elasticsearch'e güvenli bağlantıyı kurar."""
    try:
        # Bağlantı parametrelerini (sertifika atlama dahil) final_dashboard.py ile senkronize ediyoruz.
        es = Elasticsearch(
            [ELASTIC_HOST],
            # Düzeltme: Tanımlı değişken isimlerini kullandık.
            basic_auth=(ELASTIC_USERNAME, ELASTIC_PASSWORD),
            verify_certs=False,
            ssl_show_warn=False
        )
        if es.ping():
            print("✅ Elasticsearch bağlantısı başarılı!")
            return es
        else:
            print("❌ Elasticsearch bağlantısı başarısız. Servis çalışmıyor olabilir.")
            return None
    except Exception as e:
        print(f"❌ Bağlantı hatası: {e}")
        return None


def create_index_if_not_exists(es_client):
    """Veri yapısını (mapping) tanımlamak için indeksi oluşturur."""
    # Coğrafi ve skor verilerinin doğru indekslenmesi önemlidir.
    mapping = {
        "properties": {
            "value": {"type": "keyword"},
            "timestamp": {"type": "date"},
            "confidence_score": {"type": "float"},
            "final_threat_score": {"type": "float"},
            "ml_risk_score": {"type": "float"},
            "anomaly_label": {"type": "integer"},
            "ioc_type": {"type": "keyword"},
            "extra_data.country": {"type": "keyword"},
        }
    }

    if not es_client.indices.exists(index=INDEX_NAME):
        es_client.indices.create(index=INDEX_NAME, mappings=mapping)
        print(f"✅ '{INDEX_NAME}' indeksi oluşturuldu.")
    else:
        print(f"ℹ️ '{INDEX_NAME}' indeksi zaten mevcut.")


def upload_data(es_client):
    """JSON dosyasındaki verileri Elasticsearch'e yükler."""
    try:
        with open(INPUT_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"❌ HATA: '{INPUT_FILE}' dosyası bulunamadı. Lütfen önce threat_data_collector.py'yi çalıştırın.")
        return
    except json.JSONDecodeError:
        print(f"❌ HATA: '{INPUT_FILE}' dosyasındaki JSON formatı bozuk.")
        return

    success_count = 0
    for doc in data:
        # Her belgeyi (IOC) Elasticsearch'e gönder, mevcutsa üzerine yazar (overwrite)
        res = es_client.index(index=INDEX_NAME, document=doc)
        if res['result'] in ['created', 'updated']:
            success_count += 1

    print(f"\n✅ BAŞARILI: Toplam {len(data)} veriden {success_count} tanesi Elasticsearch'e yüklendi.")


if __name__ == "__main__":
    es_client = connect_to_elasticsearch()
    if es_client:
        create_index_if_not_exists(es_client)
        upload_data(es_client)
