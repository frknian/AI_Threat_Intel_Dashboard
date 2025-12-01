🛡️ AI Destekli Siber Tehdit İstihbaratı Dashboardu

Bu proje, internetten Açık Kaynak Tehdit İstihbaratı (OSINT) verilerini toplar, basit Makine Öğrenimi (ML) teknikleriyle analiz eder ve sonuçları interaktif bir Streamlit Dashboardu aracılığıyla görselleştirir. Kurumların potansiyel siber saldırı göstergelerini (IoC) önceliklendirmesini ve hızla tepki vermesini amaçlayan bir mezuniyet projesidir.

✨ Temel Özellikler

Pasif IoC Toplama: Şüpheli IP adresleri, alan adları ve URL'ler gibi göstergeler, popüler OSINT kaynaklarından (AbuseIPDB, URLScan.io) düzenli olarak çekilir.

Makine Öğrenimi ile Anomali Tespiti: Toplanan veriler, Isolation Forest algoritması kullanılarak analiz edilir. Bu, normal veri dağılımından sapan ve potansiyel olarak yeni tehditlere işaret eden aykırı değerleri (Anomalileri) tespit eder.

Hibrit Risk Puanlaması: Kaynak API'lerin güven puanları ile ML tarafından tespit edilen anomali skoru birleştirilerek, IoC'lere nihai bir risk puanı (final_threat_score) atanır.

İnteraktif Dashboard: Tüm analiz sonuçları, Streamlit tabanlı modern bir web arayüzünde metrikler, dağılım grafikleri ve en riskli öğelerin listesi şeklinde sunulur.

Güvenli Altyapı: Veri depolama ve sorgulama için güvenliği aktif olan Elasticsearch kullanılmıştır.

⚙️ Teknoloji Yığını (Tech Stack)

Bu proje üç ana katmandan oluşmaktadır:

Veri Katmanı (Persistence)

Araçlar: Elasticsearch 9.x, elasticsearch

Açıklama: Yüksek hacimli IoC verilerini depolama ve hızlı sorgulama.

Analiz Katmanı (Backend)

Araçlar: Python (3.x), pandas, scikit-learn

Açıklama: Veri işleme, özellik mühendisliği ve ML (Isolation Forest) analizi.

Sunum Katmanı (Frontend)

Araçlar: Streamlit, plotly, streamlit-folium

Açıklama: Interaktif, görselleştirilmiş dashboard arayüzü (Kibana'ya alternatif).

🚀 Başlangıç Kılavuzu

Projeyi yerel makinenizde (veya bir sunucuda Docker ile) çalıştırmak için aşağıdaki adımları izleyin:

1. Ortam Kurulumu

Elasticsearch Kurulumu: Elasticsearch 9.x versiyonunu indirin ve Windows Servisi olarak kurup başlatın.

API Anahtarları: AbuseIPDB ve URLScan.io adreslerinden ücretsiz API anahtarlarınızı alın.

Sanal Ortam: Projenin kök dizininde bir Python Sanal Ortamı (.venv) oluşturun ve aktive edin.

Bağımlılıklar: Gerekli tüm Python kütüphanelerini kurun:

pip install elasticsearch pandas scikit-learn numpy streamlit streamlit-folium plotly requests matplotlib


2. Yapılandırma

Tüm Python dosyalarının (örneğin ai_analyzer.py) başındaki yapılandırma bloklarını kendi anahtarlarınız ve şifrenizle güncelleyin.

3. Çalıştırma Sırası

Proje, verinin akış sırasına göre art arda çalıştırılmalıdır:

Veri Toplama: python threat_data_collector.py

Veri Yükleme: python db_uploader.py

AI Analizi & Skorlama: python ai_analyzer.py

Dashboard'u Başlatma: streamlit run final_dashboard.py

🛠️ Modül Dosyaları

final_dashboard.py: Ana web uygulaması ve görselleştirme mantığı.

ai_analyzer.py: Isolation Forest modelini uygulayan ve final_threat_score'u hesaplayan çekirdek analiz motoru.

db_uploader.py: Yerel JSON dosyasını Elasticsearch'e indeksleme aracı.

threat_data_collector.py: API isteklerini yöneten ve ham veriyi normalleştiren betik.

requirements.txt: Python bağımlılık listesi.

🤝 Katkıda Bulunma

Bu proje açık kaynaklı bir mezuniyet projesidir. Geri bildirimleriniz ve katkılarınız memnuniyetle karşılanır. Lütfen bir Pull Request göndermekten veya bir Issue açmaktan çekinmeyin.