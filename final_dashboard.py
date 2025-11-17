import streamlit as st
from elasticsearch import Elasticsearch
import pandas as pd
import plotly.express as px
import folium
from streamlit_folium import folium_static
import json
import warnings
import numpy as np
import matplotlib.pyplot as plt


# pandas uyarılarını gizle
warnings.filterwarnings('ignore')

# --- YAPILANDIRMA ---
ELASTIC_HOST = "https://localhost:9200"
ELASTIC_USERNAME = "elastic"
ELASTIC_PASSWORD = "yRFjrY9G-h9a188KWrjE"
INDEX_NAME = "threat_iocs"

# --- ELASTICSEARCH İŞLEMLERİ ---
@st.cache_data(ttl=600)
def fetch_data_from_es():
    """Elasticsearch'ten verileri çeker ve DataFrame olarak döndürür. Veri temizliğini yapar."""
    try:
        # Güvenlik ve sertifika atlama ayarları
        es = Elasticsearch(
            [ELASTIC_HOST],
            basic_auth=(ELASTIC_USERNAME, ELASTIC_PASSWORD),
            verify_certs=False,
            ssl_show_warn=False
        )

        if not es.ping():
            st.error("Elasticsearch bağlantısı başarısız. Lütfen Elasticsearch sunucusunun çalıştığından emin olun.")
            return pd.DataFrame()

        search_body = {
            "query": {"match_all": {}},
            "size": 10000
        }

        res = es.search(index=INDEX_NAME, body=search_body)

        data_list = [doc['_source'] for doc in res['hits']['hits']]
        df = pd.DataFrame(data_list)

        if df.empty:
            st.warning("Elasticsearch'ten veri çekilemedi.")
            return pd.DataFrame()

        # Gerekli ML/Analiz sütunlarını kontrol et
        required_columns = ['final_threat_score', 'anomaly_label', 'ioc_type', 'value', 'source']
        if 'final_threat_score' not in df.columns:
             st.warning("Verilerde 'final_threat_score' bulunamadı. Lütfen önce ai_analyzer.py'yi çalıştırın.")
             # Dashboard'un çökmesini engellemek için dummy sütunlar ekle
             df['final_threat_score'] = 0.5
             df['anomaly_label'] = 1

        # Veri tiplerini düzenle (Görselleştirme için Sayısal Tipler)
        for col in ['final_threat_score', 'confidence_score', 'ml_risk_score', 'anomaly_label']:
            if col in df.columns:
                df[col] = pd.to_numeric(df[col], errors='coerce')

        df = df.dropna(subset=['final_threat_score', 'ioc_type'])

        # extra_data sütununu dict'e dönüştür (JSON verisi olabilir)
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

        return df

    except Exception as e:
        st.error(f"Veri çekme sırasında hata: {e}")
        return pd.DataFrame()


# --- GÖRSELLEŞTİRME FONKSİYONLARI ---

def create_threat_score_gauge(df):
    """Ortalama Tehdit Puanını gösteren gösterge oluşturur."""
    if df.empty or 'final_threat_score' not in df.columns:
        return

    avg_score = df['final_threat_score'].mean() * 100

    fig = px.bar(
        x=[avg_score],
        y=['Ortalama Tehdit Puanı (%)'],
        orientation='h',
        range_x=[0, 100],
        color=[avg_score],
        color_continuous_scale=px.colors.sequential.Reds,
        labels={'x': 'Puan (%)'},
        height=150
    )
    fig.update_layout(
        showlegend=False,
        margin=dict(l=10, r=10, t=30, b=10),
        coloraxis_showscale=False
    )
    fig.update_traces(marker_line_width=0, text=f"{avg_score:.2f}%", textposition="outside")
    st.plotly_chart(fig, use_container_width=True)


def create_ioc_type_distribution(df):
    """IOC tipine göre dağılım grafiği oluşturur."""
    if df.empty or 'ioc_type' not in df.columns or 'anomaly_label' not in df.columns:
        return

    df_counts = df.groupby(['ioc_type', 'anomaly_label']).size().reset_index(name='Count')

    # Anomali etiketini okunabilir hale getir
    df_counts['Anomaly Status'] = df_counts['anomaly_label'].apply(
        lambda x: "🚨 ANOMALİ (ML Tespiti)" if x == -1 else "✔️ NORMAL"
    )

    fig = px.sunburst(
        df_counts,
        path=['ioc_type', 'Anomaly Status'],
        values='Count',
        color='Anomaly Status',
        color_discrete_map={
            '🚨 ANOMALİ (ML Tespiti)': 'red',
            '✔️ NORMAL': 'green'
        },
        title='IOC Tipi ve Anomali Durumu Dağılımı'
    )
    st.plotly_chart(fig, use_container_width=True)


def create_threat_map(df):
    """Coğrafi dağılım grafiği gösterir."""
    if df.empty or 'extra_data' not in df.columns:
        return

    # Sadece AbuseIPDB'den gelen ve ülke kodu olan verileri al
    df_geo = df[(df['source'] == 'AbuseIPDB') &
                (df['extra_data'].apply(lambda x: isinstance(x, dict) and x.get('country') is not None))].copy()

    if df_geo.empty:
        st.info("AbuseIPDB'den coğrafi veri bulunamadı.")
        return

    # Ülke kodlarını çıkar ve grupla
    df_geo['country_code'] = df_geo['extra_data'].apply(lambda x: x.get('country', 'Unknown'))

    df_map = df_geo.groupby('country_code').agg(
        ioc_count=('value', 'count'),
        avg_score=('final_threat_score', 'mean')
    ).reset_index()

    st.markdown("### 🗺️ Tehdit Coğrafi Dağılımı")
    st.write("Harita üzerinde en yüksek ortalama tehdit skoruna sahip ülkeler gösterilmektedir.")

    df_top_countries = df_map.sort_values(by='avg_score', ascending=False).head(10)

    if df_top_countries.empty:
        st.info("Gösterilecek ülke verisi yok.")
        return

    fig_bar = px.bar(
        df_top_countries,
        x='country_code',
        y='ioc_count',
        color='avg_score',
        color_continuous_scale=px.colors.sequential.OrRd,
        title='En Çok Tehdit Gelen Ülkeler (IOC Sayısı)',
        labels={'country_code': 'Ülke Kodu', 'ioc_count': 'IOC Sayısı', 'avg_score': 'Ort. Tehdit Skoru'}
    )
    st.plotly_chart(fig_bar, use_container_width=True)


# --- ANA DASHBOARD AKIŞI ---
def main_dashboard():
    """Streamlit uygulamasının ana yapısı."""
    st.set_page_config(layout="wide", page_title="Tehdit İstihbaratı Dashboard")
    st.title("🛡️ AI Destekli Tehdit İstihbaratı Dashboardu")
    st.markdown("---")

    df = fetch_data_from_es()

    if df.empty:
        st.warning(
            "Elasticsearch'ten veri çekilemedi. Lütfen sunucuların çalıştığından ve şifrenin doğru olduğundan emin olun.")
        return

    # Ana metrikler
    total_iocs = len(df)
    anomalies = len(df[df['anomaly_label'] == -1]) if 'anomaly_label' in df.columns else 0
    max_score = df['final_threat_score'].max() * 100 if 'final_threat_score' in df.columns else 0

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric("Toplam Analiz Edilen IOC", total_iocs)
    with col2:
        st.metric("🚨 ML Tarafından Tespit Edilen Anomali", anomalies)
    with col3:
        st.metric("En Yüksek Tehdit Puanı", f"{max_score:.2f}%", delta=f"Riskli: {anomalies}")
    with col4:
        st.markdown("**Ortalama Risk Seviyesi**")
        create_threat_score_gauge(df)

    # Dashboard Gövdeleri
    st.markdown("## Analiz ve Görselleştirmeler")

    col_a, col_b = st.columns([1, 1.5])

    with col_a:
        st.markdown("### IOC Tipleri ve Anomali Dağılımı")
        create_ioc_type_distribution(df)

    with col_b:
        create_threat_map(df)

    st.markdown("---")
    st.markdown("### Detaylı Tehdit Listesi (En Yüksek Riskli)")

    # Detaylı liste
    df_display = df.sort_values(by='final_threat_score', ascending=False).head(20)

    # Sütunları düzenle - sadece mevcut sütunları al
    display_columns = ['value', 'ioc_type', 'final_threat_score', 'confidence_score',
                       'ml_risk_score', 'anomaly_label', 'source']
    available_columns = [col for col in display_columns if col in df_display.columns]

    df_display_filtered = df_display[available_columns].copy()

    # Görsel iyileştirme
    if 'final_threat_score' in df_display_filtered.columns:
        st.dataframe(
            df_display_filtered.style.background_gradient(subset=['final_threat_score'], cmap='Reds'),
            use_container_width=True
        )
    else:
        st.dataframe(df_display_filtered, use_container_width=True)


if __name__ == "__main__":
    main_dashboard()
