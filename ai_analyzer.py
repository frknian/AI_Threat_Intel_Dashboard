import json
from elasticsearch import Elasticsearch
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
import warnings

warnings.filterwarnings('ignore')

# --- YAPILANDIRMA ---
ELASTIC_HOST = "https://localhost:9200"
ELASTIC_USERNAME = "elastic"
ELASTIC_PASSWORD = "yRFjrY9G-h9a188KWrjE"
INDEX_NAME = "threat_iocs"


# --- ELASTICSEARCH İŞLEMLERİ ---
def connect_to_elasticsearch():
    """Elasticsearch bağlantısını kurar."""
    try:
        es = Elasticsearch(
            [ELASTIC_HOST],
            basic_auth=(ELASTIC_USERNAME, ELASTIC_PASSWORD),
            verify_certs=False,
            ssl_show_warn=False
        )
        if es.ping():
            return es
        else:
            print("❌ HATA: Elasticsearch bağlantısı başarısız. Sunucu çalışmıyor olabilir.")
            return None
    except Exception as e:
        print(f"❌ HATA: Bağlantı sırasında genel hata: {e}")
        return None


def fetch_all_data(es_client):
    """Elasticsearch'ten tüm verileri çeker."""
    print("ℹ️ Elasticsearch'ten veri çekiliyor...")
    search_body = {
        "query": {"match_all": {}},
        "size": 10000
    }
    try:
        res = es_client.search(index=INDEX_NAME, body=search_body)
        data_list = [doc['_source'] for doc in res['hits']['hits']]

        if not data_list:
            print(f"UYARI: '{INDEX_NAME}' indeksinde hiç veri bulunamadı. Lütfen db_uploader.py'yi çalıştırın.")
            return pd.DataFrame()

        df = pd.DataFrame(data_list)
        print(f"✅ Toplam {len(df)} adet veri çekildi.")
        return df
    except Exception as e:
        print(f"❌ HATA: Veri çekme sırasında hata (İndeks adı doğru mu?): {e}")
        return pd.DataFrame()


# --- MAKİNE ÖĞRENİMİ ANALİZİ ---
def perform_anomaly_detection(df):
    """Isolation Forest kullanarak anomali tespiti yapar ve skorları ekler."""
    print("\n⚙️ Makine Öğrenimi analizi başlatılıyor...")

    features = ['confidence_score', 'extra_data_report_count']

    # 1. Feature Engineering
    if 'extra_data' in df.columns:
        def safe_json_parse(x):
            if pd.isna(x) or x == '':
                return {}
            if isinstance(x, dict):
                return x
            try:
                return json.loads(x) if isinstance(x, str) else {}
            except:
                return {}

        df['extra_data'] = df['extra_data'].apply(safe_json_parse)

        df['extra_data_report_count'] = df['extra_data'].apply(
            lambda x: x.get('report_count', 0) if isinstance(x, dict) else 0
        )

    df['confidence_score'] = pd.to_numeric(df['confidence_score'], errors='coerce').fillna(0)
    df['extra_data_report_count'] = pd.to_numeric(df['extra_data_report_count'], errors='coerce').fillna(0)

    # NaN veya Sonsuz değerleri temizleme/doldurma (ML modelinin çökmesini engeller)
    X = df[['confidence_score', 'extra_data_report_count']].values
    X[np.isnan(X)] = 0  # NaN'ları 0 ile değiştir
    X[np.isinf(X)] = 0  # Sonsuz değerleri 0 ile değiştir

    # 2. Isolation Forest Modelini Eğitme
    model = IsolationForest(contamination='auto', random_state=42)

    try:
        model.fit(X)

        df['anomaly_label'] = model.predict(X)
        df['ml_risk_score'] = model.decision_function(X)

        # 3. Nihai Tehdit Puanını Hesaplama
        min_ml = df['ml_risk_score'].min()
        max_ml = df['ml_risk_score'].max()

        # ML skorunu 0 ile 1 arasına normalize et (düşük skor = yüksek risk)
        df['ml_risk_score_norm'] = 1 - ((df['ml_risk_score'] - min_ml) / (max_ml - min_ml))

        # Final Skor: Mevcut Risk + ML Tarafından Tespit Edilen Risk
        df['final_threat_score'] = (
                df['confidence_score'] * 0.7 +
                df['ml_risk_score_norm'] * 0.3
        )

        anomalies_found = len(df[df['anomaly_label'] == -1])
        print(f"✅ Anomali tespiti tamamlandı. Tespit edilen aykırı IOC sayısı: {anomalies_found}")

        return df

    except Exception as e:
        print(f"❌ HATA: Makine Öğrenimi model hatası: {e}")
        return df


def update_elasticsearch(es_client, df):
    """Hesaplanan skorları Elasticsearch'teki belgelere geri yazar."""
    print("\n⬆️ Elasticsearch'teki belgeler güncelleniyor...")

    # NaN değerlerini 0'a çevir
    df['final_threat_score'] = df['final_threat_score'].fillna(0)
    df['ml_risk_score'] = df['ml_risk_score'].fillna(0)

    df_update = df[['value', 'ioc_type', 'final_threat_score', 'ml_risk_score', 'anomaly_label']].copy()

    success_count = 0

    try:
        for index, row in df_update.iterrows():
            # Güncellenecek skorları ve etiketleri hazırla
            update_data = {
                "final_threat_score": float(row['final_threat_score']),
                "ml_risk_score": float(row['ml_risk_score']),
                "anomaly_label": int(row['anomaly_label'])
            }

            # Belgeyi bulmak için sorgu
            search_query = {
                "query": {
                    "bool": {
                        "must": [
                            {"term": {"value": row['value']}},
                            {"term": {"ioc_type": row['ioc_type']}}
                        ]
                    }
                }
            }

            res_search = es_client.search(index=INDEX_NAME, body=search_query, size=1)

            if res_search['hits']['total']['value'] > 0:
                doc_id = res_search['hits']['hits'][0]['_id']

                # Belgeyi skorlarla güncelle
                es_client.update(index=INDEX_NAME, id=doc_id, body={"doc": update_data})
                success_count += 1

                if row['anomaly_label'] == -1:
                    print(f"   🚨 ANOMALİ TESPİT EDİLDİ: {row['value']} - Final Risk: {row['final_threat_score']:.2f}")

    except Exception as e:
        print(f"❌ HATA: Elasticsearch güncelleme sırasında hata: {e}")

    print(f"✅ {success_count} adet belge güncellendi.")


def main():
    """AI analiz akışını yönetir."""
    es = connect_to_elasticsearch()
    if es is None:
        return

    df = fetch_all_data(es)
    if df.empty:
        return

    df_analyzed = perform_anomaly_detection(df)

    if not df_analyzed.empty:
        update_elasticsearch(es, df_analyzed)

    print(f"\n--- AI Analizi ve Güncelleme TAMAMLANDI ---")


if __name__ == "__main__":
    main()
