"""
EDA Module: Logon Activity Analysis
Analyzes login/logoff patterns from the CERT r4.2 logon.csv dataset.
Detects after-hours logins, multi-PC usage, session anomalies.
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


def load_logon_data(data_path: str) -> pd.DataFrame:
    """Load and parse the logon.csv file."""
    print("[EDA-Logon] Loading logon.csv...")
    df = pd.read_csv(data_path)
    df['date'] = pd.to_datetime(df['date'], format='%m/%d/%Y %H:%M:%S')
    df['hour'] = df['date'].dt.hour
    df['day_of_week'] = df['date'].dt.dayofweek  # 0=Monday
    df['month'] = df['date'].dt.to_period('M')
    df['is_after_hours'] = (df['hour'] < 6) | (df['hour'] >= 22)
    df['is_weekend'] = df['day_of_week'] >= 5
    print(f"[EDA-Logon] Loaded {len(df):,} records")
    return df


def analyze_logon_patterns(df: pd.DataFrame, output_dir: str):
    """Generate logon pattern analysis and visualizations."""
    os.makedirs(output_dir, exist_ok=True)
    
    # ── 1. Logon Activity by Hour of Day ──
    print("[EDA-Logon] Generating hourly activity distribution...")
    fig, axes = plt.subplots(1, 2, figsize=(16, 6))
    fig.patch.set_facecolor('#0d1117')
    
    logon_df = df[df['activity'] == 'Logon']
    
    # Hourly distribution
    ax = axes[0]
    ax.set_facecolor('#161b22')
    hourly = logon_df['hour'].value_counts().sort_index()
    colors = ['#ff4444' if h < 6 or h >= 22 else '#00d4ff' for h in hourly.index]
    ax.bar(hourly.index, hourly.values, color=colors, edgecolor='none', alpha=0.85)
    ax.set_xlabel('Hour of Day', color='white', fontsize=11)
    ax.set_ylabel('Login Count', color='white', fontsize=11)
    ax.set_title('Login Activity by Hour', color='#00d4ff', fontsize=14, fontweight='bold')
    ax.tick_params(colors='white')
    ax.spines['bottom'].set_color('#30363d')
    ax.spines['left'].set_color('#30363d')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.axvspan(-0.5, 5.5, alpha=0.1, color='red', label='After-hours')
    ax.axvspan(21.5, 23.5, alpha=0.1, color='red')
    ax.legend(facecolor='#161b22', edgecolor='#30363d', labelcolor='white')
    
    # Day of week distribution
    ax = axes[1]
    ax.set_facecolor('#161b22')
    daily = logon_df['day_of_week'].value_counts().sort_index()
    day_names = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']
    colors_dow = ['#ff4444' if d >= 5 else '#00d4ff' for d in daily.index]
    ax.bar([day_names[i] for i in daily.index], daily.values, color=colors_dow, edgecolor='none', alpha=0.85)
    ax.set_xlabel('Day of Week', color='white', fontsize=11)
    ax.set_ylabel('Login Count', color='white', fontsize=11)
    ax.set_title('Login Activity by Day', color='#00d4ff', fontsize=14, fontweight='bold')
    ax.tick_params(colors='white')
    ax.spines['bottom'].set_color('#30363d')
    ax.spines['left'].set_color('#30363d')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'logon_hourly_daily.png'), dpi=150, bbox_inches='tight',
                facecolor='#0d1117', edgecolor='none')
    plt.close()
    
    # ── 2. After-Hours Login Heatmap per User (Top 30) ──
    print("[EDA-Logon] Generating after-hours heatmap...")
    after_hours = logon_df[logon_df['is_after_hours']]
    top_after_hours_users = after_hours['user'].value_counts().head(30)
    
    if len(top_after_hours_users) > 0:
        fig, ax = plt.subplots(figsize=(14, 8))
        fig.patch.set_facecolor('#0d1117')
        ax.set_facecolor('#161b22')
        
        # Build heatmap data: user x hour
        heatmap_users = top_after_hours_users.index.tolist()
        ah_data = after_hours[after_hours['user'].isin(heatmap_users)]
        pivot = ah_data.groupby(['user', 'hour']).size().unstack(fill_value=0)
        pivot = pivot.loc[heatmap_users]
        
        sns.heatmap(pivot, cmap='YlOrRd', ax=ax, cbar_kws={'label': 'Login Count'},
                    linewidths=0.5, linecolor='#30363d')
        ax.set_title('After-Hours Logins — Top 30 Suspicious Users', color='#ff4444',
                     fontsize=14, fontweight='bold')
        ax.set_xlabel('Hour', color='white', fontsize=11)
        ax.set_ylabel('User ID', color='white', fontsize=11)
        ax.tick_params(colors='white', labelsize=8)
        cbar = ax.collections[0].colorbar
        cbar.ax.yaxis.set_tick_params(color='white')
        plt.setp(cbar.ax.yaxis.get_ticklabels(), color='white')
        cbar.set_label('Login Count', color='white')
        
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, 'logon_afterhours_heatmap.png'), dpi=150,
                    bbox_inches='tight', facecolor='#0d1117', edgecolor='none')
        plt.close()
    
    # ── 3. Multi-PC Access Analysis ──
    print("[EDA-Logon] Analyzing multi-PC access patterns...")
    user_pc = logon_df.groupby('user')['pc'].nunique().reset_index()
    user_pc.columns = ['user', 'unique_pcs']
    multi_pc = user_pc[user_pc['unique_pcs'] > 2].sort_values('unique_pcs', ascending=False)
    
    fig, ax = plt.subplots(figsize=(14, 6))
    fig.patch.set_facecolor('#0d1117')
    ax.set_facecolor('#161b22')
    
    top_multi = multi_pc.head(25)
    bars = ax.barh(top_multi['user'], top_multi['unique_pcs'], color='#ff6b35', edgecolor='none', alpha=0.85)
    ax.set_xlabel('Number of Unique PCs Accessed', color='white', fontsize=11)
    ax.set_ylabel('User ID', color='white', fontsize=11)
    ax.set_title('Multi-PC Access — Top 25 Users', color='#ff6b35', fontsize=14, fontweight='bold')
    ax.tick_params(colors='white', labelsize=8)
    ax.spines['bottom'].set_color('#30363d')
    ax.spines['left'].set_color('#30363d')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.invert_yaxis()
    
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'logon_multi_pc.png'), dpi=150,
                bbox_inches='tight', facecolor='#0d1117', edgecolor='none')
    plt.close()
    
    # ── 4. Generate per-user logon features ──
    print("[EDA-Logon] Computing per-user logon features...")
    logon_only = logon_df.copy()
    
    user_features = logon_only.groupby('user').agg(
        total_logins=('id', 'count'),
        avg_login_hour=('hour', 'mean'),
        std_login_hour=('hour', 'std'),
        after_hours_logins=('is_after_hours', 'sum'),
        weekend_logins=('is_weekend', 'sum'),
        unique_pcs=('pc', 'nunique'),
        login_days_span=('date', lambda x: (x.max() - x.min()).days),
    ).reset_index()
    
    user_features['after_hours_ratio'] = user_features['after_hours_logins'] / user_features['total_logins']
    user_features['weekend_ratio'] = user_features['weekend_logins'] / user_features['total_logins']
    user_features['std_login_hour'] = user_features['std_login_hour'].fillna(0)
    
    # Save features
    features_path = os.path.join(output_dir, 'logon_features.csv')
    user_features.to_csv(features_path, index=False)
    print(f"[EDA-Logon] Saved {len(user_features)} user features to {features_path}")
    
    # ── 5. Summary statistics ──
    stats = {
        'total_records': len(df),
        'total_logons': len(logon_df),
        'total_logoffs': len(df[df['activity'] == 'Logoff']),
        'unique_users': df['user'].nunique(),
        'unique_pcs': df['pc'].nunique(),
        'after_hours_logins': int(logon_df['is_after_hours'].sum()),
        'weekend_logins': int(logon_df['is_weekend'].sum()),
        'multi_pc_users': len(multi_pc),
        'date_range': f"{df['date'].min()} to {df['date'].max()}",
    }
    
    stats_df = pd.DataFrame(list(stats.items()), columns=['Metric', 'Value'])
    stats_df.to_csv(os.path.join(output_dir, 'logon_stats.csv'), index=False)
    
    print("[EDA-Logon] ✓ Analysis complete!")
    for k, v in stats.items():
        print(f"  {k}: {v}")
    
    return user_features


def run(data_dir: str, output_dir: str) -> pd.DataFrame:
    """Main entry point for logon EDA."""
    logon_path = os.path.join(data_dir, 'logon.csv')
    out_path = os.path.join(output_dir, 'logon')
    df = load_logon_data(logon_path)
    features = analyze_logon_patterns(df, out_path)
    return features


if __name__ == '__main__':
    DATA_DIR = os.path.join(os.path.dirname(__file__), '..', 'Models', 'Data set', 'r4.2')
    OUTPUT_DIR = os.path.join(os.path.dirname(__file__), 'outputs')
    run(DATA_DIR, OUTPUT_DIR)
