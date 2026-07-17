"""
EDA Module: Psychometric Analysis
Analyzes Big Five (OCEAN) personality trait data from psychometric.csv.
Correlates personality profiles with potential insider threat indicators.
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


TRAIT_NAMES = {
    'O': 'Openness',
    'C': 'Conscientiousness',
    'E': 'Extraversion',
    'A': 'Agreeableness',
    'N': 'Neuroticism',
}

TRAIT_COLORS = {
    'O': '#00d4ff',
    'C': '#10b981',
    'E': '#f59e0b',
    'A': '#a855f7',
    'N': '#ff4444',
}


def load_psychometric_data(data_path: str) -> pd.DataFrame:
    """Load psychometric.csv file."""
    print("[EDA-Psychometric] Loading psychometric.csv...")
    df = pd.read_csv(data_path)
    print(f"[EDA-Psychometric] Loaded {len(df):,} employee records")
    return df


def analyze_psychometric(df: pd.DataFrame, output_dir: str):
    """Generate psychometric analysis and visualizations."""
    os.makedirs(output_dir, exist_ok=True)
    
    traits = ['O', 'C', 'E', 'A', 'N']
    
    # ── 1. Trait Distribution Plots ──
    print("[EDA-Psychometric] Generating trait distributions...")
    fig, axes = plt.subplots(1, 5, figsize=(20, 5))
    fig.patch.set_facecolor('#0d1117')
    fig.suptitle('OCEAN Personality Trait Distributions', color='#00d4ff',
                fontsize=16, fontweight='bold', y=1.02)
    
    for i, trait in enumerate(traits):
        ax = axes[i]
        ax.set_facecolor('#161b22')
        ax.hist(df[trait], bins=20, color=TRAIT_COLORS[trait], edgecolor='#161b22', alpha=0.85)
        ax.set_title(TRAIT_NAMES[trait], color=TRAIT_COLORS[trait], fontsize=12, fontweight='bold')
        ax.set_xlabel('Score', color='white', fontsize=9)
        ax.set_ylabel('Count', color='white', fontsize=9)
        ax.tick_params(colors='white', labelsize=8)
        ax.spines['bottom'].set_color('#30363d')
        ax.spines['left'].set_color('#30363d')
        ax.spines['top'].set_visible(False)
        ax.spines['right'].set_visible(False)
        
        # Add mean line
        mean_val = df[trait].mean()
        ax.axvline(mean_val, color='white', linestyle='--', linewidth=1, alpha=0.7)
        ax.text(mean_val + 0.5, ax.get_ylim()[1] * 0.9, f'μ={mean_val:.1f}',
               color='white', fontsize=8)
    
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'psychometric_distributions.png'), dpi=150,
                bbox_inches='tight', facecolor='#0d1117', edgecolor='none')
    plt.close()
    
    # ── 2. Correlation Matrix ──
    print("[EDA-Psychometric] Generating correlation matrix...")
    fig, ax = plt.subplots(figsize=(8, 7))
    fig.patch.set_facecolor('#0d1117')
    ax.set_facecolor('#161b22')
    
    corr = df[traits].corr()
    mask = np.triu(np.ones_like(corr, dtype=bool))
    sns.heatmap(corr, mask=mask, annot=True, fmt='.3f', cmap='RdYlBu_r',
                center=0, ax=ax, linewidths=1, linecolor='#30363d',
                xticklabels=[TRAIT_NAMES[t] for t in traits],
                yticklabels=[TRAIT_NAMES[t] for t in traits],
                cbar_kws={'label': 'Correlation'})
    ax.set_title('Personality Trait Correlations', color='#00d4ff',
                fontsize=14, fontweight='bold')
    ax.tick_params(colors='white')
    
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'psychometric_correlation.png'), dpi=150,
                bbox_inches='tight', facecolor='#0d1117', edgecolor='none')
    plt.close()
    
    # ── 3. Risk Profile Clustering ──
    print("[EDA-Psychometric] Identifying high-risk personality profiles...")
    # High neuroticism + Low agreeableness + Low conscientiousness = higher risk
    df['risk_score_personality'] = (
        (50 - df['A']) * 0.35 +  # Low agreeableness
        df['N'] * 0.35 +          # High neuroticism
        (50 - df['C']) * 0.30     # Low conscientiousness
    )
    df['risk_score_personality'] = (
        (df['risk_score_personality'] - df['risk_score_personality'].min()) /
        (df['risk_score_personality'].max() - df['risk_score_personality'].min()) * 100
    )
    
    fig, ax = plt.subplots(figsize=(12, 6))
    fig.patch.set_facecolor('#0d1117')
    ax.set_facecolor('#161b22')
    
    scatter = ax.scatter(df['A'], df['N'], c=df['risk_score_personality'],
                        cmap='RdYlGn_r', s=30, alpha=0.7, edgecolors='none')
    cbar = plt.colorbar(scatter, ax=ax)
    cbar.set_label('Personality Risk Score', color='white')
    cbar.ax.yaxis.set_tick_params(color='white')
    plt.setp(cbar.ax.yaxis.get_ticklabels(), color='white')
    
    ax.set_xlabel('Agreeableness', color='white', fontsize=11)
    ax.set_ylabel('Neuroticism', color='white', fontsize=11)
    ax.set_title('Personality Risk Landscape (Low A + High N = Higher Risk)',
                color='#ff4444', fontsize=14, fontweight='bold')
    ax.tick_params(colors='white')
    ax.spines['bottom'].set_color('#30363d')
    ax.spines['left'].set_color('#30363d')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'psychometric_risk_landscape.png'), dpi=150,
                bbox_inches='tight', facecolor='#0d1117', edgecolor='none')
    plt.close()
    
    # Prepare features
    psych_features = df[['user_id', 'O', 'C', 'E', 'A', 'N', 'risk_score_personality']].copy()
    psych_features = psych_features.rename(columns={'user_id': 'user'})
    
    features_path = os.path.join(output_dir, 'psychometric_features.csv')
    psych_features.to_csv(features_path, index=False)
    print(f"[EDA-Psychometric] Saved {len(psych_features)} user features to {features_path}")
    
    # Stats
    stats = {
        'total_employees': len(df),
        'mean_openness': f"{df['O'].mean():.1f}",
        'mean_conscientiousness': f"{df['C'].mean():.1f}",
        'mean_extraversion': f"{df['E'].mean():.1f}",
        'mean_agreeableness': f"{df['A'].mean():.1f}",
        'mean_neuroticism': f"{df['N'].mean():.1f}",
        'high_risk_count': int((df['risk_score_personality'] > 70).sum()),
    }
    stats_df = pd.DataFrame(list(stats.items()), columns=['Metric', 'Value'])
    stats_df.to_csv(os.path.join(output_dir, 'psychometric_stats.csv'), index=False)
    
    print("[EDA-Psychometric] ✓ Analysis complete!")
    for k, v in stats.items():
        print(f"  {k}: {v}")
    
    return psych_features


def run(data_dir: str, output_dir: str) -> pd.DataFrame:
    """Main entry point for psychometric EDA."""
    psych_path = os.path.join(data_dir, 'psychometric.csv')
    out_path = os.path.join(output_dir, 'psychometric')
    df = load_psychometric_data(psych_path)
    features = analyze_psychometric(df, out_path)
    return features


if __name__ == '__main__':
    DATA_DIR = os.path.join(os.path.dirname(__file__), '..', 'Models', 'Data set', 'r4.2')
    OUTPUT_DIR = os.path.join(os.path.dirname(__file__), 'outputs')
    run(DATA_DIR, OUTPUT_DIR)
