#!/usr/bin/env bash
set -e
python simulator/attack_simulator.py --output data/generated_logs.csv --events 1500
streamlit run dashboard/app.py
