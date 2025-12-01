from elasticsearch import Elasticsearch, AuthenticationException, ConnectionError
import warnings
import sys

# Uyarıları gizle
warnings.filterwarnings('ignore')

# --- AYARLAR ---
ELASTIC_HOST = "https://localhost:9200"
ELASTIC_USERNAME = "elastic"
ELASTIC_PASSWORD = "yRFjrY9G-h9a188KWrjE"
INDEX_NAME = "threat_iocs"


def check_system():
    print(f"--- Elasticsearch Detaylı Bağlantı Testi ---")
    print(f"Hedef: {ELASTIC_HOST}")
    print(f"Kullanıcı: {ELASTIC_USERNAME}")

    # 1. Bağlantı Testi
    try:
        es = Elasticsearch(
            [ELASTIC_HOST],
            basic_auth=(ELASTIC_USERNAME, ELASTIC_PASSWORD),
            verify_certs=False,
            ssl_show_warn=False,
            request_timeout=10  # 10 saniye bekle
        )

        if not es.ping():
            print("\n❌ BAŞARISIZ: Sunucuya 'Ping' atılamadı.")
            print("   Olası Nedenler:")
            print("   1. Servis 'Running' olsa bile henüz tam başlamamış olabilir (1 dk bekleyin).")
            print("   2. Güvenlik duvarı 9200 portunu engelliyor olabilir.")
            return

        info = es.info()
        print(f"\n✅ BAŞARILI: Sunucuya bağlanıldı!")
        print(f"   Sürüm: {info['version']['number']}")
        print(f"   Küme Adı: {info['cluster_name']}")

    except AuthenticationException:
        print("\n❌ KİMLİK DOĞRULAMA HATASI (401)")
        print("   -> Şifreniz YANLIŞ. Lütfen 'elasticsearch-reset-password' ile şifreyi sıfırlayın.")
        print("   -> Ardından bu dosyadaki ELASTIC_PASSWORD değişkenini güncelleyin.")
        return
    except ConnectionError:
        print("\n❌ BAŞARISIZ: Bağlantı Reddedildi (Connection Refused)")
        print("   -> Sunucu şu an çalışmıyor veya 9200 portuna erişilemiyor.")
        print("   -> Hizmetler'den Elasticsearch servisini kontrol edin.")
        return
    except Exception as e:
        print(f"\n❌ BEKLENMEYEN HATA: {e}")
        return

    # 2. İndeks ve Veri Kontrolü
    print(f"\n--- İndeks ({INDEX_NAME}) Kontrolü ---")
    try:
        if not es.indices.exists(index=INDEX_NAME):
            print(f"❌ HATA: '{INDEX_NAME}' indeksi BULUNAMADI.")
            print("   -> ÇÖZÜM: 'python db_uploader.py' dosyasını çalıştırarak verileri yükleyin.")
            return

        count = es.count(index=INDEX_NAME)['count']
        print(f"✅ İndeks mevcut. Toplam Kayıt Sayısı: {count}")

        if count == 0:
            print("⚠️ UYARI: İndeks var ama içi BOŞ.")
            return

        # 3. Skor Alanı Kontrolü
        res = es.search(index=INDEX_NAME, size=1)
        if res['hits']['hits']:
            doc = res['hits']['hits'][0]['_source']
            if 'final_threat_score' in doc:
                print("✅ VERİ DURUMU: 'final_threat_score' hesaplanmış. Dashboard çalışmaya hazır.")
            else:
                print("⚠️ EKSİK VERİ: 'final_threat_score' alanı yok.")
                print("   -> ÇÖZÜM: 'python ai_analyzer.py' dosyasını çalıştırın.")

    except Exception as e:
        print(f"❌ Veri okuma hatası: {e}")


if __name__ == "__main__":
    check_system()