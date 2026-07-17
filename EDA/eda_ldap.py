"""
EDA Module: LDAP / Organizational Structure Analysis
Analyzes monthly LDAP snapshots to track employee departures,
organizational structure, and role changes.
"""

import pandas as pd
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns
import os
import glob
import warnings
warnings.filterwarnings('ignore')


def load_ldap_data(ldap_dir: str) -> tuple:
    """Load all monthly LDAP snapshots and track changes."""
    print("[EDA-LDAP] Loading LDAP monthly snapshots...")
    
    files = sorted(glob.glob(os.path.join(ldap_dir, '*.csv')))
    monthly_data = {}
    all_users = set()
    
    for f in files:
        month = os.path.basename(f).replace('.csv', '')
        df = pd.read_csv(f)
        monthly_data[month] = df
        all_users.update(df['user_id'].tolist())
        print(f"  {month}: {len(df)} employees")
    
    print(f"[EDA-LDAP] Loaded {len(files)} monthly snapshots, {len(all_users)} unique users")
    return monthly_data, all_users


def analyze_ldap(monthly_data: dict, all_users: set, output_dir: str):
    """Analyze organizational changes and employee departures."""
    os.makedirs(output_dir, exist_ok=True)
    
    months = sorted(monthly_data.keys())
    
    # ── 1. Employee Count Over Time ──
    print("[EDA-LDAP] Tracking headcount and attrition...")
    headcount = {m: len(df) for m, df in monthly_data.items()}
    
    # Track departures
    departures = {}
    for i in range(1, len(months)):
        prev_users = set(monthly_data[months[i-1]]['user_id'])
        curr_users = set(monthly_data[months[i]]['user_id'])
        departed = prev_users - curr_users
        departures[months[i]] = departed
    
    fig, axes = plt.subplots(1, 2, figsize=(16, 6))
    fig.patch.set_facecolor('#0d1117')
    
    ax = axes[0]
    ax.set_facecolor('#161b22')
    ax.plot(range(len(months)), [headcount[m] for m in months], color='#00d4ff',
            linewidth=2, marker='o', markersize=6, markerfacecolor='#10b981',
            markeredgecolor='none')
    ax.fill_between(range(len(months)), [headcount[m] for m in months],
                    alpha=0.15, color='#00d4ff')
    ax.set_xlabel('Month', color='white', fontsize=11)
    ax.set_ylabel('Employee Count', color='white', fontsize=11)
    ax.set_title('Headcount Over Time', color='#00d4ff', fontsize=14, fontweight='bold')
    ax.set_xticks(range(len(months)))
    ax.set_xticklabels(months, rotation=45, ha='right', fontsize=8)
    ax.tick_params(colors='white')
    ax.spines['bottom'].set_color('#30363d')
    ax.spines['left'].set_color('#30363d')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    
    # Monthly departures
    ax = axes[1]
    ax.set_facecolor('#161b22')
    dep_months = list(departures.keys())
    dep_counts = [len(departures[m]) for m in dep_months]
    ax.bar(range(len(dep_months)), dep_counts, color='#ff4444', edgecolor='none', alpha=0.85)
    ax.set_xlabel('Month', color='white', fontsize=11)
    ax.set_ylabel('Departures', color='white', fontsize=11)
    ax.set_title('Monthly Employee Departures', color='#ff4444', fontsize=14, fontweight='bold')
    ax.set_xticks(range(len(dep_months)))
    ax.set_xticklabels(dep_months, rotation=45, ha='right', fontsize=8)
    ax.tick_params(colors='white')
    ax.spines['bottom'].set_color('#30363d')
    ax.spines['left'].set_color('#30363d')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'ldap_headcount_attrition.png'), dpi=150,
                bbox_inches='tight', facecolor='#0d1117', edgecolor='none')
    plt.close()
    
    # ── 2. Department Distribution ──
    print("[EDA-LDAP] Analyzing departmental structure...")
    latest_month = months[-1]
    latest_df = monthly_data[latest_month]
    
    fig, axes = plt.subplots(1, 2, figsize=(16, 6))
    fig.patch.set_facecolor('#0d1117')
    
    ax = axes[0]
    ax.set_facecolor('#161b22')
    dept_counts = latest_df['department'].value_counts().head(10)
    palette = sns.color_palette('viridis', len(dept_counts))
    ax.barh(dept_counts.index, dept_counts.values, color=palette, edgecolor='none', alpha=0.85)
    ax.set_xlabel('Employee Count', color='white', fontsize=11)
    ax.set_title(f'Department Distribution ({latest_month})', color='#00d4ff',
                fontsize=14, fontweight='bold')
    ax.tick_params(colors='white', labelsize=8)
    ax.spines['bottom'].set_color('#30363d')
    ax.spines['left'].set_color('#30363d')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.invert_yaxis()
    
    # Role distribution
    ax = axes[1]
    ax.set_facecolor('#161b22')
    role_counts = latest_df['role'].value_counts().head(10)
    palette2 = sns.color_palette('magma', len(role_counts))
    ax.barh(role_counts.index, role_counts.values, color=palette2, edgecolor='none', alpha=0.85)
    ax.set_xlabel('Employee Count', color='white', fontsize=11)
    ax.set_title(f'Role Distribution ({latest_month})', color='#a855f7',
                fontsize=14, fontweight='bold')
    ax.tick_params(colors='white', labelsize=8)
    ax.spines['bottom'].set_color('#30363d')
    ax.spines['left'].set_color('#30363d')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.invert_yaxis()
    
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'ldap_dept_roles.png'), dpi=150,
                bbox_inches='tight', facecolor='#0d1117', edgecolor='none')
    plt.close()
    
    # ── 3. Build per-user LDAP features ──
    print("[EDA-LDAP] Building per-user LDAP features...")
    
    # Use latest snapshot for role/dept features, track who departed
    first_df = monthly_data[months[0]]
    all_departed = set()
    for m in dep_months:
        all_departed.update(departures[m])
    
    # Merge first appearance with departure info
    ldap_features = first_df[['user_id', 'role', 'business_unit', 'functional_unit',
                              'department', 'team']].copy()
    ldap_features = ldap_features.rename(columns={'user_id': 'user'})
    ldap_features['left_company'] = ldap_features['user'].isin(all_departed).astype(int)
    
    features_path = os.path.join(output_dir, 'ldap_features.csv')
    ldap_features.to_csv(features_path, index=False)
    print(f"[EDA-LDAP] Saved {len(ldap_features)} user features to {features_path}")
    
    # Stats
    total_departed = len(all_departed)
    stats = {
        'months_covered': len(months),
        'initial_headcount': headcount[months[0]],
        'final_headcount': headcount[months[-1]],
        'total_departed': total_departed,
        'attrition_rate': f"{total_departed / headcount[months[0]] * 100:.1f}%",
        'unique_departments': latest_df['department'].nunique(),
        'unique_roles': latest_df['role'].nunique(),
    }
    stats_df = pd.DataFrame(list(stats.items()), columns=['Metric', 'Value'])
    stats_df.to_csv(os.path.join(output_dir, 'ldap_stats.csv'), index=False)
    
    print("[EDA-LDAP] ✓ Analysis complete!")
    for k, v in stats.items():
        print(f"  {k}: {v}")
    
    return ldap_features


def run(data_dir: str, output_dir: str) -> pd.DataFrame:
    """Main entry point for LDAP EDA."""
    ldap_dir = os.path.join(data_dir, 'LDAP')
    out_path = os.path.join(output_dir, 'ldap')
    monthly_data, all_users = load_ldap_data(ldap_dir)
    features = analyze_ldap(monthly_data, all_users, out_path)
    return features


if __name__ == '__main__':
    DATA_DIR = os.path.join(os.path.dirname(__file__), '..', 'Models', 'Data set', 'r4.2')
    OUTPUT_DIR = os.path.join(os.path.dirname(__file__), 'outputs')
    run(DATA_DIR, OUTPUT_DIR)
