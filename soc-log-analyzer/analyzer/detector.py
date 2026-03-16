from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import pandas as pd


@dataclass
class DetectionConfig:
    brute_force_threshold: int = 5
    brute_force_window: str = '5min'
    suspicious_fail_threshold: int = 8
    risk_critical: float = 8.5
    risk_high: float = 7.0
    risk_medium: float = 5.0


REQUIRED_COLUMNS = {
    'timestamp', 'source_ip', 'username', 'event_type', 'status', 'country', 'lat', 'lon'
}


def load_logs(path: str | Path) -> pd.DataFrame:
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f'Log file not found: {path}')

    if path.suffix.lower() == '.csv':
        df = pd.read_csv(path)
    elif path.suffix.lower() in {'.json', '.jsonl'}:
        df = pd.read_json(path, lines=path.suffix.lower() == '.jsonl')
    else:
        raise ValueError('Unsupported file format. Use CSV, JSON, or JSONL.')

    missing = REQUIRED_COLUMNS - set(df.columns)
    if missing:
        raise ValueError(f'Missing required columns: {sorted(missing)}')

    df['timestamp'] = pd.to_datetime(df['timestamp'], utc=True, errors='coerce')
    df = df.dropna(subset=['timestamp']).sort_values('timestamp').reset_index(drop=True)
    return df


def _severity_from_score(score: float, config: DetectionConfig) -> str:
    if score >= config.risk_critical:
        return 'Critical'
    if score >= config.risk_high:
        return 'High'
    if score >= config.risk_medium:
        return 'Medium'
    return 'Low'


def detect_brute_force(df: pd.DataFrame, config: DetectionConfig | None = None) -> pd.DataFrame:
    config = config or DetectionConfig()
    failures = df[df['status'].eq('failure')].copy()
    if failures.empty:
        return pd.DataFrame(columns=['source_ip', 'first_seen', 'last_seen', 'attempt_count', 'usernames', 'country'])

    results: list[dict] = []
    for ip, group in failures.groupby('source_ip'):
        g = group.sort_values('timestamp').copy()
        g = g.set_index('timestamp')
        rolling_counts = g['status'].rolling(config.brute_force_window).count()
        peak = int(rolling_counts.max()) if not rolling_counts.empty else 0
        if peak >= config.brute_force_threshold:
            peak_time = rolling_counts.idxmax()
            window_start = peak_time - pd.Timedelta(config.brute_force_window)
            window_df = group[(group['timestamp'] >= window_start) & (group['timestamp'] <= peak_time)]
            results.append(
                {
                    'source_ip': ip,
                    'first_seen': window_df['timestamp'].min(),
                    'last_seen': window_df['timestamp'].max(),
                    'attempt_count': len(window_df),
                    'usernames': ', '.join(sorted(window_df['username'].dropna().astype(str).unique()[:5])),
                    'country': window_df['country'].mode().iloc[0] if not window_df['country'].mode().empty else 'Unknown',
                    'risk_score': round(min(10.0, 5.0 + peak * 0.65), 1),
                    'detection_type': 'Brute Force',
                }
            )
    out = pd.DataFrame(results)
    if not out.empty:
        out['severity'] = out['risk_score'].apply(lambda s: _severity_from_score(s, config))
    return out.sort_values(['risk_score', 'attempt_count'], ascending=False).reset_index(drop=True)


def detect_suspicious_ips(df: pd.DataFrame, config: DetectionConfig | None = None) -> pd.DataFrame:
    config = config or DetectionConfig()
    agg = (
        df.groupby(['source_ip', 'country', 'lat', 'lon'], dropna=False)
        .agg(
            total_events=('event_type', 'count'),
            failed_logins=('status', lambda s: int((s == 'failure').sum())),
            successful_logins=('status', lambda s: int((s == 'success').sum())),
            first_seen=('timestamp', 'min'),
            last_seen=('timestamp', 'max'),
            distinct_users=('username', 'nunique'),
        )
        .reset_index()
    )
    if agg.empty:
        return agg

    agg['success_ratio'] = (agg['successful_logins'] / agg['total_events']).fillna(0)
    agg['risk_score'] = (
        agg['failed_logins'] * 0.55
        + (agg['distinct_users'] * 0.45)
        + ((1 - agg['success_ratio']) * 3.5)
        + (agg['total_events'] * 0.04)
    ).clip(upper=10).round(1)
    agg['severity'] = agg['risk_score'].apply(lambda s: _severity_from_score(s, config))

    suspicious = agg[
        (agg['failed_logins'] >= config.suspicious_fail_threshold)
        | (agg['risk_score'] >= config.risk_medium)
    ].copy()
    return suspicious.sort_values(['risk_score', 'failed_logins'], ascending=False).reset_index(drop=True)


def build_event_table(
    brute_force_alerts: pd.DataFrame,
    suspicious_ips: pd.DataFrame,
) -> pd.DataFrame:
    rows: list[dict] = []

    for _, row in brute_force_alerts.iterrows():
        rows.append(
            {
                'asset': 'auth-service',
                'source_ip': row['source_ip'],
                'risk_score': row['risk_score'],
                'detection_type': row['detection_type'],
                'severity': row['severity'],
                'country': row['country'],
                'status': 'Active',
                'notes': f"{row['attempt_count']} failed logins targeting {row['usernames'] or 'multiple users'}",
            }
        )

    for _, row in suspicious_ips.head(15).iterrows():
        rows.append(
            {
                'asset': 'edge-gateway',
                'source_ip': row['source_ip'],
                'risk_score': row['risk_score'],
                'detection_type': 'Suspicious IP',
                'severity': row['severity'],
                'country': row['country'],
                'status': 'Investigating' if row['risk_score'] < 8.5 else 'Escalated',
                'notes': f"{row['failed_logins']} failed / {row['total_events']} total events",
            }
        )

    event_table = pd.DataFrame(rows).drop_duplicates(subset=['source_ip', 'detection_type'])
    if event_table.empty:
        return pd.DataFrame(columns=['asset', 'source_ip', 'risk_score', 'detection_type', 'severity', 'country', 'status', 'notes'])
    return event_table.sort_values(['risk_score', 'severity'], ascending=[False, True]).reset_index(drop=True)


def summarize_metrics(df: pd.DataFrame, events: pd.DataFrame) -> dict:
    counts = events['severity'].value_counts().to_dict() if not events.empty else {}
    return {
        'Critical': int(counts.get('Critical', 0)),
        'High': int(counts.get('High', 0)),
        'Medium': int(counts.get('Medium', 0)),
        'Low': int(counts.get('Low', 0)),
        'Unique IPs': int(df['source_ip'].nunique()),
        'Total Events': int(len(df)),
    }


def login_heatmap(df: pd.DataFrame) -> pd.DataFrame:
    tmp = df.copy()
    tmp['hour'] = tmp['timestamp'].dt.hour
    tmp['minute_bucket'] = (tmp['timestamp'].dt.minute // 10) * 10
    tmp['time_bucket'] = tmp['hour'].astype(str).str.zfill(2) + ':' + tmp['minute_bucket'].astype(str).str.zfill(2)
    heat = tmp.groupby(['source_ip', 'time_bucket']).size().reset_index(name='count')
    return heat


def recent_alerts(events: pd.DataFrame, limit: int = 6) -> list[str]:
    if events.empty:
        return ['No active alerts.']
    alerts: list[str] = []
    for _, row in events.head(limit).iterrows():
        alerts.append(
            f"[{row['severity']}] {row['detection_type']} from {row['source_ip']} ({row['country']}) — score {row['risk_score']}"
        )
    return alerts


def analyze(path: str | Path, config: DetectionConfig | None = None) -> dict:
    config = config or DetectionConfig()
    logs = load_logs(path)
    brute_force = detect_brute_force(logs, config)
    suspicious_ips = detect_suspicious_ips(logs, config)
    events = build_event_table(brute_force, suspicious_ips)
    metrics = summarize_metrics(logs, events)
    heatmap = login_heatmap(logs)
    alerts = recent_alerts(events)
    return {
        'logs': logs,
        'brute_force_alerts': brute_force,
        'suspicious_ips': suspicious_ips,
        'events': events,
        'metrics': metrics,
        'heatmap': heatmap,
        'alerts': alerts,
    }
