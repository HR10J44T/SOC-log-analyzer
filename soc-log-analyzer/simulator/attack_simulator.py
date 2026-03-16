from __future__ import annotations

import argparse
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd

NORMAL_USERS = ['arya', 'admin', 'ubuntu', 'service', 'analyst', 'backup']
ATTACK_USERS = ['root', 'admin', 'test', 'guest', 'oracle', 'jenkins']
EVENT_TYPES = ['login', 'api_request', 'ssh_auth']
USER_AGENTS = ['OpenSSH', 'cURL', 'Browser', 'Python-Requests', 'Nmap-Script']
TARGETS = ['/login', '/api/auth', '/ssh', '/vpn', '/admin']

LOCATIONS = [
    ('India', 20.5937, 78.9629),
    ('United States', 37.0902, -95.7129),
    ('Germany', 51.1657, 10.4515),
    ('Brazil', -14.2350, -51.9253),
    ('Singapore', 1.3521, 103.8198),
    ('Russia', 61.5240, 105.3188),
    ('Netherlands', 52.1326, 5.2913),
    ('United Kingdom', 55.3781, -3.4360),
]

MALICIOUS_LOCATIONS = [
    ('Russia', 55.7558, 37.6173),
    ('China', 39.9042, 116.4074),
    ('North Korea', 39.0392, 125.7625),
    ('Romania', 44.4268, 26.1025),
]


def random_ip() -> str:
    return '.'.join(str(random.randint(1, 254)) for _ in range(4))


def generate_logs(total_events: int = 1500, seed: int = 7) -> pd.DataFrame:
    random.seed(seed)
    now = datetime.now(timezone.utc).replace(second=0, microsecond=0)
    start = now - timedelta(hours=24)
    rows: list[dict] = []

    normal_ips = [random_ip() for _ in range(40)]
    attacker_ips = [random_ip() for _ in range(5)]

    for _ in range(total_events):
        ts = start + timedelta(minutes=random.randint(0, 24 * 60 - 1), seconds=random.randint(0, 59))
        ip = random.choice(normal_ips)
        country, lat, lon = random.choice(LOCATIONS)
        success = random.random() > 0.12
        rows.append(
            {
                'timestamp': ts.isoformat(),
                'source_ip': ip,
                'username': random.choice(NORMAL_USERS),
                'event_type': random.choice(EVENT_TYPES),
                'status': 'success' if success else 'failure',
                'country': country,
                'lat': lat + random.uniform(-1.8, 1.8),
                'lon': lon + random.uniform(-1.8, 1.8),
                'target': random.choice(TARGETS),
                'user_agent': random.choice(USER_AGENTS),
            }
        )

    # Inject brute-force patterns
    for attacker_ip in attacker_ips:
        country, lat, lon = random.choice(MALICIOUS_LOCATIONS)
        attack_start = start + timedelta(hours=random.randint(4, 22), minutes=random.randint(0, 40))
        burst_size = random.randint(9, 18)
        for i in range(burst_size):
            ts = attack_start + timedelta(seconds=i * random.randint(10, 25))
            rows.append(
                {
                    'timestamp': ts.isoformat(),
                    'source_ip': attacker_ip,
                    'username': random.choice(ATTACK_USERS),
                    'event_type': 'ssh_auth',
                    'status': 'failure' if i < burst_size - 1 else random.choice(['failure', 'success']),
                    'country': country,
                    'lat': lat + random.uniform(-0.8, 0.8),
                    'lon': lon + random.uniform(-0.8, 0.8),
                    'target': random.choice(['/ssh', '/admin', '/vpn']),
                    'user_agent': random.choice(['Hydra', 'Ncrack', 'OpenSSH']),
                }
            )

    df = pd.DataFrame(rows).sort_values('timestamp').reset_index(drop=True)
    return df


def main() -> None:
    parser = argparse.ArgumentParser(description='Generate fake SOC logs with attack traffic.')
    parser.add_argument('--output', type=str, default='data/generated_logs.csv', help='Path to output CSV file')
    parser.add_argument('--events', type=int, default=1500, help='Number of baseline events to generate')
    parser.add_argument('--seed', type=int, default=7, help='Random seed')
    args = parser.parse_args()

    df = generate_logs(total_events=args.events, seed=args.seed)
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(output_path, index=False)
    print(f'Generated {len(df)} events at {output_path}')


if __name__ == '__main__':
    main()
