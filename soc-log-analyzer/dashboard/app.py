from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.append(str(ROOT))

from analyzer.detector import analyze  # noqa: E402

st.set_page_config(page_title='SOC Threat Monitor', layout='wide', initial_sidebar_state='expanded')


def inject_css() -> None:
    st.markdown(
        """
        <style>
        .stApp {
            background: radial-gradient(circle at top left, #17122f 0%, #0b0f1c 45%, #090b14 100%);
            color: #f3f4ff;
        }
        [data-testid="stSidebar"] {
            background: linear-gradient(180deg, #090b14 0%, #0f1022 100%);
            border-right: 1px solid rgba(144, 97, 249, 0.18);
        }
        .metric-card {
            background: linear-gradient(135deg, rgba(95,58,181,0.35), rgba(27,20,53,0.92));
            border: 1px solid rgba(151, 116, 255, 0.18);
            border-radius: 18px;
            padding: 18px 20px;
            box-shadow: 0 10px 30px rgba(18, 12, 42, 0.45);
        }
        .panel-card {
            background: rgba(13, 16, 31, 0.88);
            border: 1px solid rgba(137, 92, 255, 0.12);
            border-radius: 20px;
            padding: 10px 14px 18px 14px;
            box-shadow: 0 12px 36px rgba(11, 9, 25, 0.4);
        }
        .alert-pill {
            background: rgba(95,58,181,0.24);
            border: 1px solid rgba(172, 146, 255, 0.2);
            padding: 10px 12px;
            border-radius: 12px;
            margin-bottom: 8px;
            font-size: 0.92rem;
        }
        h1, h2, h3 {
            color: #f6f5ff !important;
        }
        .subtle {
            color: #b9b6d7;
            font-size: 0.92rem;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def metric_card(label: str, value: int, delta: str) -> None:
    st.markdown(
        f"""
        <div class="metric-card">
            <div class="subtle">{label}</div>
            <div style="font-size: 2rem; font-weight: 700; margin-top: 8px;">{value}</div>
            <div style="margin-top: 10px; color: #8ef0a4; font-size: 0.85rem;">{delta}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def panel_open(title: str, subtitle: str = '') -> None:
    st.markdown('<div class="panel-card">', unsafe_allow_html=True)
    st.markdown(f'### {title}')
    if subtitle:
        st.markdown(f'<div class="subtle">{subtitle}</div>', unsafe_allow_html=True)


def panel_close() -> None:
    st.markdown('</div>', unsafe_allow_html=True)


inject_css()

st.sidebar.markdown('## Orca SOC')
st.sidebar.caption('Purple-haze threat monitoring dashboard')
module = st.sidebar.radio(
    'Modules',
    ['Dashboard', 'Log Discovery', 'API Security', 'Cloud Infrastructure', 'Attack Paths', 'Vulnerabilities'],
    index=0,
)

st.sidebar.markdown('---')
log_path = st.sidebar.text_input('Log file path', value=str(ROOT / 'data' / 'generated_logs.csv'))
refresh = st.sidebar.button('Refresh Analysis')
st.sidebar.markdown('---')
st.sidebar.markdown('**Trial period**: 28 days left')

if refresh:
    st.cache_data.clear()

@st.cache_data(show_spinner=False)
def load_analysis(path: str):
    return analyze(path)

analysis = load_analysis(log_path)
metrics = analysis['metrics']
logs = analysis['logs']
suspicious_ips = analysis['suspicious_ips']
events = analysis['events']
heatmap = analysis['heatmap']

st.title('API Security')
st.caption(f'Live SOC telemetry • {module} • {pd.Timestamp.utcnow().strftime("%d %b %Y %H:%M UTC") }')

c1, c2, c3, c4 = st.columns(4)
with c1:
    metric_card('Critical', metrics['Critical'], '+0.30% this hour')
with c2:
    metric_card('High', metrics['High'], '+0.18% this hour')
with c3:
    metric_card('Medium', metrics['Medium'], '+0.44% this hour')
with c4:
    metric_card('Low', metrics['Low'], '+0.11% this hour')

left, right = st.columns([1.55, 1])

with left:
    panel_open('Top Address Activity', '10-minute buckets reveal bursts and brute-force behavior')
    if heatmap.empty:
        st.info('No heatmap data available.')
    else:
        top_ips = suspicious_ips['source_ip'].head(8).tolist() if not suspicious_ips.empty else logs['source_ip'].value_counts().head(8).index.tolist()
        heat = heatmap[heatmap['source_ip'].isin(top_ips)].copy()
        fig = px.density_heatmap(
            heat,
            x='time_bucket',
            y='source_ip',
            z='count',
            histfunc='sum',
            color_continuous_scale='Purples',
        )
        fig.update_layout(
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            margin=dict(l=0, r=0, t=10, b=0),
            xaxis_title='',
            yaxis_title='',
            font=dict(color='#ece9ff'),
        )
        st.plotly_chart(fig, use_container_width=True)
    panel_close()

with right:
    panel_open('IP Addresses', 'Geographic origin of suspicious activity')
    if suspicious_ips.empty:
        st.info('No suspicious IP locations found.')
    else:
        geo = suspicious_ips.copy()
        fig = px.scatter_geo(
            geo,
            lat='lat',
            lon='lon',
            size='risk_score',
            hover_name='source_ip',
            hover_data={'country': True, 'failed_logins': True, 'risk_score': True, 'lat': False, 'lon': False},
            projection='natural earth',
        )
        fig.update_traces(marker=dict(opacity=0.8, line=dict(width=0)))
        fig.update_layout(
            paper_bgcolor='rgba(0,0,0,0)',
            geo=dict(bgcolor='rgba(0,0,0,0)', showland=True, landcolor='rgb(22,25,46)', countrycolor='rgb(60,60,90)'),
            margin=dict(l=0, r=0, t=0, b=0),
            font=dict(color='#ece9ff'),
        )
        st.plotly_chart(fig, use_container_width=True)
    panel_close()

bottom_left, bottom_mid = st.columns([1.05, 1.35])

with bottom_left:
    panel_open('External Exposure', 'Public-facing areas currently receiving hostile traffic')
    exposures = [
        'SSH endpoint on /ssh receiving repeated authentication failures',
        'Admin panel /admin targeted by password spraying activity',
        'VPN gateway /vpn showing multi-country access attempts',
        'API authentication path /api/auth under elevated probing',
    ]
    for idx, item in enumerate(exposures, start=1):
        st.markdown(f'**{idx}.** {item}')
    st.markdown('---')
    st.markdown('#### Active Alerts')
    for alert in analysis['alerts']:
        st.markdown(f'<div class="alert-pill">{alert}</div>', unsafe_allow_html=True)
    panel_close()

with bottom_mid:
    panel_open('View Results By', 'Prioritized event queue for investigation')
    if events.empty:
        st.info('No detections generated yet.')
    else:
        display_df = events[['asset', 'source_ip', 'risk_score', 'detection_type', 'severity', 'status', 'notes']].copy()
        st.dataframe(display_df, use_container_width=True, hide_index=True)
    panel_close()

st.markdown('### Raw Log Stream')
st.dataframe(logs.tail(200), use_container_width=True, hide_index=True)
