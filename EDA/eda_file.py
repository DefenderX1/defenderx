"""
EDA Module: File Transfer Analysis
Analyzes file copy events (to removable media) from file.csv.
Detects data exfiltration patterns, after-hours transfers, volume anomalies.
"""

import pandas as pd
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns
import os
import warnings
warnings.filterwarnings('ignore')


def load_file_data(data_path: str) -> pd.DataFrame:
    """Load and parse the file.csv file."""
    print("[EDA-File] Loading file.csv...")
    df = pd.read_csv(data_path)
    df['date'] = pd.to_datetime(df['date'], format='%m/%d/%Y %H:%M:%S')
    df['hour'] = df['date'].dt.hour
    df['day_of_week'] = df['date'].dt.dayofweek
    df['month'] = df['date'].dt.to_period('M')
    df['is_after_hours'] = (df['hour'] < 6) | (df['hour'] >= 22)
    df['is_weekend'] = df['day_of_week'] >= 5
    
    # Extract file extension
    df['extension'] = df['filename'].str.extract(r'\.(\w+)$', expand=False).str.lower()
    df['extension'] = df['extension'].fillna('unknown')
    
    # Estimate content size (character count as proxy)
    df['content_length'] = df['content'].str.len().fillna(0)
    
    print(f"[EDA-File] Loaded {len(df):,} records")
    return df


def analyze_file_patterns(df: pd.DataFrame, output_dir: str):
    """Generate file transfer analysis and visualizations."""
    os.makedirs(output_dir, exist_ok=True)
    
    # ── 1. File Copy Volume by Hour and Day ──
    print("[EDA-File] Generating file transfer patterns...")
    fig, axes = plt.subplots(1, 2, figsize=(16, 6))
    fig.patch.set_facecolor('#0d1117')
    
    ax = axes[0]
    ax.set_facecolor('#161b22')
    hourly = df['hour'].value_counts().sort_index()
    colors = ['#ff4444' if h < 6 or h >= 22 else '#10b981' for h in hourly.index]
    ax.bar(hourly.index, hourly.values, color=colors, edgecolor='none', alpha=0.85)
    ax.set_xlabel('Hour of Day', color='white', fontsize=11)
    ax.set_ylabel('File Copies', color='white', fontsize=11)
    ax.set_title('File Copies to Removable Media by Hour', color='#10b981',
                fontsize=14, fontweight='bold')
    ax.tick_params(colors='white')
    ax.spines['bottom'].set_color('#30363d')
    ax.spines['left'].set_color('#30363d')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.axvspan(-0.5, 5.5, alpha=0.1, color='red')
    ax.axvspan(21.5, 23.5, alpha=0.1, color='red')
    
    # File type distribution
    ax = axes[1]
    ax.set_facecolor('#161b22')
    ext_counts = df['extension'].value_counts().head(10)
    palette = sns.color_palette('viridis', len(ext_counts))
    bars = ax.barh(ext_counts.index, ext_counts.values, color=palette, edgecolor='none', alpha=0.85)
    ax.set_xlabel('Count', color='white', fontsize=11)
    ax.set_ylabel('File Extension', color='white', fontsize=11)
    ax.set_title('Top 10 File Types Copied', color='#10b981', fontsize=14, fontweight='bold')
    ax.tick_params(colors='white')
    ax.spines['bottom'].set_color('#30363d')
    ax.spines['left'].set_color('#30363d')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.invert_yaxis()
    
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'file_hourly_types.png'), dpi=150,
                bbox_inches='tight', facecolor='#0d1117', edgecolor='none')
    plt.close()
    
    # ── 2. Top File Copiers ──
    print("[EDA-File] Identifying top file copiers...")
    user_files = df.groupby('user').agg(
        file_copy_count=('id', 'count'),
        file_copy_after_hours=('is_after_hours', 'sum'),
        file_copy_weekend=('is_weekend', 'sum'),
        file_unique_pcs=('pc', 'nunique'),
        file_unique_extensions=('extension', 'nunique'),
        file_avg_content_len=('content_length', 'mean'),
        file_total_content_len=('content_length', 'sum'),
    ).reset_index()
    user_files['file_after_hours_ratio'] = user_files['file_copy_after_hours'] / user_files['file_copy_count']
    user_files = user_files.sort_values('file_copy_count', ascending=False)
    
    fig, ax = plt.subplots(figsize=(14, 8))
    fig.patch.set_facecolor('#0d1117')
    ax.set_facecolor('#161b22')
    
    top30 = user_files.head(30)
    colors = ['#ff4444' if r > 0.1 else '#10b981' for r in top30['file_after_hours_ratio']]
    ax.barh(top30['user'], top30['file_copy_count'], color=colors, edgecolor='none', alpha=0.85)
    ax.set_xlabel('Files Copied to Removable Media', color='white', fontsize=11)
    ax.set_ylabel('User ID', color='white', fontsize=11)
    ax.set_title('Top 30 File Copiers (Red = High After-Hours Ratio)',
                color='#10b981', fontsize=14, fontweight='bold')
    ax.tick_params(colors='white', labelsize=8)
    ax.spines['bottom'].set_color('#30363d')
    ax.spines['left'].set_color('#30363d')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.invert_yaxis()
    
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'file_top_copiers.png'), dpi=150,
                bbox_inches='tight', facecolor='#0d1117', edgecolor='none')
    plt.close()
    
    # ── 3. Monthly File Copy Trend ──
    print("[EDA-File] Generating monthly trend...")
    fig, ax = plt.subplots(figsize=(14, 5))
    fig.patch.set_facecolor('#0d1117')
    ax.set_facecolor('#161b22')
    
    monthly = df.groupby('month').size()
    ax.plot(range(len(monthly)), monthly.values, color='#10b981', linewidth=2,
            marker='o', markersize=6, markerfacecolor='#00d4ff', markeredgecolor='none')
    ax.fill_between(range(len(monthly)), monthly.values, alpha=0.15, color='#10b981')
    ax.set_xlabel('Month', color='white', fontsize=11)
    ax.set_ylabel('Files Copied', color='white', fontsize=11)
    ax.set_title('File Copy Activity Over Time', color='#10b981', fontsize=14, fontweight='bold')
    ax.set_xticks(range(len(monthly)))
    ax.set_xticklabels([str(m) for m in monthly.index], rotation=45, ha='right', fontsize=8)
    ax.tick_params(colors='white')
    ax.spines['bottom'].set_color('#30363d')
    ax.spines['left'].set_color('#30363d')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'file_monthly_trend.png'), dpi=150,
                bbox_inches='tight', facecolor='#0d1117', edgecolor='none')
    plt.close()
    
    # Save features
    features_path = os.path.join(output_dir, 'file_features.csv')
    user_files.to_csv(features_path, index=False)
    print(f"[EDA-File] Saved {len(user_files)} user features to {features_path}")
    
    # Stats
    stats = {
        'total_file_copies': len(df),
        'unique_users': df['user'].nunique(),
        'unique_files': df['filename'].nunique(),
        'after_hours_copies': int(df['is_after_hours'].sum()),
        'weekend_copies': int(df['is_weekend'].sum()),
        'top_extension': ext_counts.index[0] if len(ext_counts) > 0 else 'N/A',
        'date_range': f"{df['date'].min()} to {df['date'].max()}",
    }
    stats_df = pd.DataFrame(list(stats.items()), columns=['Metric', 'Value'])
    stats_df.to_csv(os.path.join(output_dir, 'file_stats.csv'), index=False)
    
    print("[EDA-File] ✓ Analysis complete!")
    for k, v in stats.items():
        print(f"  {k}: {v}")
    
    return user_files


def run(data_dir: str, output_dir: str) -> pd.DataFrame:
    """Main entry point for file EDA."""
    file_path = os.path.join(data_dir, 'file.csv')
    out_path = os.path.join(output_dir, 'file')
    df = load_file_data(file_path)
    features = analyze_file_patterns(df, out_path)
    return features


if __name__ == '__main__':
    DATA_DIR = os.path.join(os.path.dirname(__file__), '..', 'Models', 'Data set', 'r4.2')
    OUTPUT_DIR = os.path.join(os.path.dirname(__file__), 'outputs')
    run(DATA_DIR, OUTPUT_DIR)
