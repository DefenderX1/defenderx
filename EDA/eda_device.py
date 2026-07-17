"""
EDA Module: USB Device Activity Analysis
Analyzes USB connect/disconnect events from device.csv.
Detects suspicious USB usage patterns, after-hours device connections.
"""

import pandas as pd
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path
import os
import warnings
warnings.filterwarnings('ignore')


def load_device_data(data_path: str) -> pd.DataFrame:
    """Load and parse the device.csv file."""
    print("[EDA-Device] Loading device.csv...")
    df = pd.read_csv(data_path)
    df['date'] = pd.to_datetime(df['date'], format='%m/%d/%Y %H:%M:%S')
    df['hour'] = df['date'].dt.hour
    df['day_of_week'] = df['date'].dt.dayofweek
    df['month'] = df['date'].dt.to_period('M')
    df['is_after_hours'] = (df['hour'] < 6) | (df['hour'] >= 22)
    df['is_weekend'] = df['day_of_week'] >= 5
    print(f"[EDA-Device] Loaded {len(df):,} records")
    return df


def analyze_device_patterns(df: pd.DataFrame, output_dir: str):
    """Generate device usage analysis and visualizations."""
    os.makedirs(output_dir, exist_ok=True)
    
    connects = df[df['activity'] == 'Connect']
    
    # ── 1. USB Connection Frequency by Hour ──
    print("[EDA-Device] Generating connection frequency plots...")
    fig, axes = plt.subplots(1, 2, figsize=(16, 6))
    fig.patch.set_facecolor('#0d1117')
    
    ax = axes[0]
    ax.set_facecolor('#161b22')
    hourly = connects['hour'].value_counts().sort_index()
    colors = ['#ff4444' if h < 6 or h >= 22 else '#a855f7' for h in hourly.index]
    ax.bar(hourly.index, hourly.values, color=colors, edgecolor='none', alpha=0.85)
    ax.set_xlabel('Hour of Day', color='white', fontsize=11)
    ax.set_ylabel('USB Connections', color='white', fontsize=11)
    ax.set_title('USB Connections by Hour', color='#a855f7', fontsize=14, fontweight='bold')
    ax.tick_params(colors='white')
    ax.spines['bottom'].set_color('#30363d')
    ax.spines['left'].set_color('#30363d')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.axvspan(-0.5, 5.5, alpha=0.1, color='red')
    ax.axvspan(21.5, 23.5, alpha=0.1, color='red')
    
    # Monthly trend
    ax = axes[1]
    ax.set_facecolor('#161b22')
    monthly = connects.groupby('month').size()
    ax.plot(range(len(monthly)), monthly.values, color='#a855f7', linewidth=2, marker='o',
            markersize=6, markerfacecolor='#00d4ff', markeredgecolor='none')
    ax.fill_between(range(len(monthly)), monthly.values, alpha=0.15, color='#a855f7')
    ax.set_xlabel('Month', color='white', fontsize=11)
    ax.set_ylabel('USB Connections', color='white', fontsize=11)
    ax.set_title('USB Activity Trend', color='#a855f7', fontsize=14, fontweight='bold')
    ax.set_xticks(range(len(monthly)))
    ax.set_xticklabels([str(m) for m in monthly.index], rotation=45, ha='right', fontsize=8)
    ax.tick_params(colors='white')
    ax.spines['bottom'].set_color('#30363d')
    ax.spines['left'].set_color('#30363d')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'device_hourly_trend.png'), dpi=150,
                bbox_inches='tight', facecolor='#0d1117', edgecolor='none')
    plt.close()
    
    # ── 2. Top USB Users (Suspicious) ──
    print("[EDA-Device] Identifying top USB users...")
    user_usb = connects.groupby('user').agg(
        usb_connects=('id', 'count'),
        usb_after_hours=('is_after_hours', 'sum'),
        usb_weekend=('is_weekend', 'sum'),
        usb_unique_pcs=('pc', 'nunique'),
    ).reset_index()
    user_usb['usb_after_hours_ratio'] = user_usb['usb_after_hours'] / user_usb['usb_connects']
    user_usb = user_usb.sort_values('usb_connects', ascending=False)
    
    fig, ax = plt.subplots(figsize=(14, 8))
    fig.patch.set_facecolor('#0d1117')
    ax.set_facecolor('#161b22')
    
    top30 = user_usb.head(30)
    colors = ['#ff4444' if r > 0.15 else '#a855f7' for r in top30['usb_after_hours_ratio']]
    ax.barh(top30['user'], top30['usb_connects'], color=colors, edgecolor='none', alpha=0.85)
    ax.set_xlabel('Total USB Connections', color='white', fontsize=11)
    ax.set_ylabel('User ID', color='white', fontsize=11)
    ax.set_title('Top 30 USB Users (Red = High After-Hours Ratio)', color='#a855f7',
                fontsize=14, fontweight='bold')
    ax.tick_params(colors='white', labelsize=8)
    ax.spines['bottom'].set_color('#30363d')
    ax.spines['left'].set_color('#30363d')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.invert_yaxis()
    
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'device_top_users.png'), dpi=150,
                bbox_inches='tight', facecolor='#0d1117', edgecolor='none')
    plt.close()
    
    # ── 3. Session Duration Analysis ──
    print("[EDA-Device] Computing USB session durations...")
    # Pair Connect/Disconnect events per user per PC
    user_sessions = []
    for (user, pc), group in df.groupby(['user', 'pc']):
        group = group.sort_values('date')
        connect_time = None
        for _, row in group.iterrows():
            if row['activity'] == 'Connect':
                connect_time = row['date']
            elif row['activity'] == 'Disconnect' and connect_time is not None:
                duration = (row['date'] - connect_time).total_seconds() / 60  # minutes
                if 0 < duration < 1440:  # Less than 24 hours
                    user_sessions.append({
                        'user': user,
                        'pc': pc,
                        'duration_min': duration,
                        'connect_hour': connect_time.hour,
                        'is_after_hours': connect_time.hour < 6 or connect_time.hour >= 22,
                    })
                connect_time = None
    
    if user_sessions:
        sessions_df = pd.DataFrame(user_sessions)
        
        fig, ax = plt.subplots(figsize=(12, 6))
        fig.patch.set_facecolor('#0d1117')
        ax.set_facecolor('#161b22')
        
        ax.hist(sessions_df['duration_min'].clip(0, 480), bins=50, color='#a855f7',
                edgecolor='#161b22', alpha=0.85)
        ax.set_xlabel('Session Duration (minutes)', color='white', fontsize=11)
        ax.set_ylabel('Frequency', color='white', fontsize=11)
        ax.set_title('USB Session Duration Distribution', color='#a855f7',
                     fontsize=14, fontweight='bold')
        ax.tick_params(colors='white')
        ax.spines['bottom'].set_color('#30363d')
        ax.spines['left'].set_color('#30363d')
        ax.spines['top'].set_visible(False)
        ax.spines['right'].set_visible(False)
        
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, 'device_session_duration.png'), dpi=150,
                    bbox_inches='tight', facecolor='#0d1117', edgecolor='none')
        plt.close()
        
        # Add session features to user_usb
        sess_features = sessions_df.groupby('user').agg(
            avg_session_min=('duration_min', 'mean'),
            max_session_min=('duration_min', 'max'),
            total_sessions=('duration_min', 'count'),
        ).reset_index()
        user_usb = user_usb.merge(sess_features, on='user', how='left')
    
    user_usb = user_usb.fillna(0)
    
    # Save features
    features_path = os.path.join(output_dir, 'device_features.csv')
    user_usb.to_csv(features_path, index=False)
    print(f"[EDA-Device] Saved {len(user_usb)} user features to {features_path}")
    
    # Stats
    stats = {
        'total_records': len(df),
        'total_connects': len(connects),
        'total_disconnects': len(df[df['activity'] == 'Disconnect']),
        'unique_users': df['user'].nunique(),
        'after_hours_connects': int(connects['is_after_hours'].sum()),
        'weekend_connects': int(connects['is_weekend'].sum()),
        'date_range': f"{df['date'].min()} to {df['date'].max()}",
    }
    stats_df = pd.DataFrame(list(stats.items()), columns=['Metric', 'Value'])
    stats_df.to_csv(os.path.join(output_dir, 'device_stats.csv'), index=False)
    
    print("[EDA-Device] ✓ Analysis complete!")
    for k, v in stats.items():
        print(f"  {k}: {v}")
    
    return user_usb


def run(data_dir: str, output_dir: str) -> pd.DataFrame:
    """Main entry point for device EDA."""
    device_path = os.path.join(data_dir, 'device.csv')
    out_path = os.path.join(output_dir, 'device')
    df = load_device_data(device_path)
    features = analyze_device_patterns(df, out_path)
    return features


if __name__ == '__main__':
    DATA_DIR = os.path.join(os.path.dirname(__file__), '..', 'Models', 'Data set', 'r4.2')
    OUTPUT_DIR = os.path.join(os.path.dirname(__file__), 'outputs')
    run(DATA_DIR, OUTPUT_DIR)
