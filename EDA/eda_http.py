"""
EDA Module: HTTP Activity Analysis (Chunked Processing)
Analyzes web browsing activity from the massive http.csv (~14.5 GB).
Uses chunked reading to handle the file size.
Detects shadow AI usage, suspicious domains, job site visits.
"""

import pandas as pd
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns
import os
import re
from urllib.parse import urlparse
from collections import Counter
import warnings
warnings.filterwarnings('ignore')


# Domain categorization patterns
SHADOW_AI_DOMAINS = [
    'chatgpt', 'openai', 'claude', 'anthropic', 'gemini', 'bard',
    'copilot', 'github.com/copilot', 'huggingface', 'perplexity',
    'poe.com', 'character.ai', 'midjourney', 'stability.ai',
    'deepseek', 'groq', 'together.ai', 'replicate',
]

JOB_SITE_DOMAINS = [
    'linkedin', 'indeed', 'glassdoor', 'monster', 'ziprecruiter',
    'careerbuilder', 'dice', 'hired', 'angel.co', 'wellfound',
    'simplyhired', 'snagajob', 'flexjobs', 'ladders', 'jobcase',
]

CLOUD_STORAGE_DOMAINS = [
    'dropbox', 'drive.google', 'onedrive', 'box.com', 'icloud',
    'mega.nz', 'mediafire', 'wetransfer', 'sendspace', 'zippyshare',
    'pastebin', 'hastebin', 'privatebin',
]

SUSPICIOUS_DOMAINS = [
    'tor', 'vpn', 'proxy', 'anonymo', 'darkweb', 'hack',
    'exploit', 'keylog', 'phish', 'malware', 'ransomware',
]


def categorize_url(url: str) -> str:
    """Categorize a URL into risk categories."""
    url_lower = url.lower() if isinstance(url, str) else ''
    
    for pattern in SHADOW_AI_DOMAINS:
        if pattern in url_lower:
            return 'Shadow AI'
    for pattern in JOB_SITE_DOMAINS:
        if pattern in url_lower:
            return 'Job Sites'
    for pattern in CLOUD_STORAGE_DOMAINS:
        if pattern in url_lower:
            return 'Cloud Storage'
    for pattern in SUSPICIOUS_DOMAINS:
        if pattern in url_lower:
            return 'Suspicious'
    return 'Normal'


def extract_domain(url: str) -> str:
    """Extract domain from URL."""
    try:
        if isinstance(url, str):
            parsed = urlparse(url)
            return parsed.netloc or parsed.path.split('/')[0]
    except Exception:
        pass
    return 'unknown'


def analyze_http_chunked(data_path: str, output_dir: str, chunk_size: int = 50000,
                         max_chunks: int = 200):
    """Process HTTP data in chunks to handle the massive file size."""
    os.makedirs(output_dir, exist_ok=True)
    
    print(f"[EDA-HTTP] Processing http.csv in chunks of {chunk_size:,}...")
    
    # Accumulators
    user_url_counts = Counter()
    user_categories = {}  # user -> {category: count}
    hourly_counts = Counter()
    domain_counts = Counter()
    category_counts = Counter()
    user_total = Counter()
    total_rows = 0
    
    try:
        reader = pd.read_csv(data_path, chunksize=chunk_size,
                             usecols=['id', 'date', 'user', 'pc', 'url'])
        
        for i, chunk in enumerate(reader):
            if i >= max_chunks:
                print(f"[EDA-HTTP] Reached max chunks ({max_chunks}), stopping...")
                break
            
            total_rows += len(chunk)
            
            # Parse dates
            chunk['date'] = pd.to_datetime(chunk['date'], format='%m/%d/%Y %H:%M:%S',
                                          errors='coerce')
            chunk['hour'] = chunk['date'].dt.hour
            
            # Categorize URLs
            chunk['category'] = chunk['url'].apply(categorize_url)
            chunk['domain'] = chunk['url'].apply(extract_domain)
            
            # Accumulate hourly counts
            for h, count in chunk['hour'].value_counts().items():
                hourly_counts[h] += count
            
            # Accumulate domain counts (top domains)
            for d, count in chunk['domain'].value_counts().items():
                domain_counts[d] += count
            
            # Accumulate category counts
            for cat, count in chunk['category'].value_counts().items():
                category_counts[cat] += count
            
            # Per-user category counts
            for (user, cat), count in chunk.groupby(['user', 'category']).size().items():
                if user not in user_categories:
                    user_categories[user] = Counter()
                user_categories[user][cat] += count
            
            # Per-user total
            for user, count in chunk['user'].value_counts().items():
                user_total[user] += count
            
            if (i + 1) % 20 == 0:
                print(f"  Processed {total_rows:,} rows ({i + 1} chunks)...")
    
    except Exception as e:
        print(f"[EDA-HTTP] Warning: Error processing chunks: {e}")
        print(f"[EDA-HTTP] Processed {total_rows:,} rows before error")
    
    print(f"[EDA-HTTP] Total rows processed: {total_rows:,}")
    
    # ── 1. Browsing by Hour ──
    print("[EDA-HTTP] Generating visualizations...")
    fig, axes = plt.subplots(1, 2, figsize=(16, 6))
    fig.patch.set_facecolor('#0d1117')
    
    ax = axes[0]
    ax.set_facecolor('#161b22')
    hours = sorted(hourly_counts.keys())
    counts = [hourly_counts[h] for h in hours]
    colors = ['#ff4444' if h < 6 or h >= 22 else '#f59e0b' for h in hours]
    ax.bar(hours, counts, color=colors, edgecolor='none', alpha=0.85)
    ax.set_xlabel('Hour of Day', color='white', fontsize=11)
    ax.set_ylabel('HTTP Requests', color='white', fontsize=11)
    ax.set_title('Web Activity by Hour', color='#f59e0b', fontsize=14, fontweight='bold')
    ax.tick_params(colors='white')
    ax.spines['bottom'].set_color('#30363d')
    ax.spines['left'].set_color('#30363d')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    
    # Category breakdown
    ax = axes[1]
    ax.set_facecolor('#161b22')
    cats = dict(category_counts.most_common(10))
    cat_colors = {
        'Normal': '#10b981', 'Shadow AI': '#ff4444', 'Job Sites': '#f59e0b',
        'Cloud Storage': '#a855f7', 'Suspicious': '#ef4444',
    }
    bar_colors = [cat_colors.get(c, '#6b7280') for c in cats.keys()]
    ax.barh(list(cats.keys()), list(cats.values()), color=bar_colors, edgecolor='none', alpha=0.85)
    ax.set_xlabel('Count', color='white', fontsize=11)
    ax.set_title('URL Category Distribution', color='#f59e0b', fontsize=14, fontweight='bold')
    ax.tick_params(colors='white')
    ax.spines['bottom'].set_color('#30363d')
    ax.spines['left'].set_color('#30363d')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.invert_yaxis()
    
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'http_hourly_categories.png'), dpi=150,
                bbox_inches='tight', facecolor='#0d1117', edgecolor='none')
    plt.close()
    
    # ── 2. Top Domains ──
    fig, ax = plt.subplots(figsize=(14, 8))
    fig.patch.set_facecolor('#0d1117')
    ax.set_facecolor('#161b22')
    
    top_domains = dict(domain_counts.most_common(25))
    ax.barh(list(top_domains.keys()), list(top_domains.values()),
            color='#f59e0b', edgecolor='none', alpha=0.85)
    ax.set_xlabel('Visit Count', color='white', fontsize=11)
    ax.set_title('Top 25 Visited Domains', color='#f59e0b', fontsize=14, fontweight='bold')
    ax.tick_params(colors='white', labelsize=8)
    ax.spines['bottom'].set_color('#30363d')
    ax.spines['left'].set_color('#30363d')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.invert_yaxis()
    
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'http_top_domains.png'), dpi=150,
                bbox_inches='tight', facecolor='#0d1117', edgecolor='none')
    plt.close()
    
    # ── 3. Build per-user HTTP features ──
    print("[EDA-HTTP] Building per-user HTTP features...")
    user_features_list = []
    for user, cats in user_categories.items():
        user_features_list.append({
            'user': user,
            'http_total': user_total[user],
            'http_shadow_ai': cats.get('Shadow AI', 0),
            'http_job_sites': cats.get('Job Sites', 0),
            'http_cloud_storage': cats.get('Cloud Storage', 0),
            'http_suspicious': cats.get('Suspicious', 0),
            'http_normal': cats.get('Normal', 0),
        })
    
    user_http_df = pd.DataFrame(user_features_list)
    if len(user_http_df) > 0:
        user_http_df['shadow_ai_ratio'] = user_http_df['http_shadow_ai'] / user_http_df['http_total']
        user_http_df['job_site_ratio'] = user_http_df['http_job_sites'] / user_http_df['http_total']
        user_http_df['suspicious_ratio'] = user_http_df['http_suspicious'] / user_http_df['http_total']
    
    features_path = os.path.join(output_dir, 'http_features.csv')
    user_http_df.to_csv(features_path, index=False)
    print(f"[EDA-HTTP] Saved {len(user_http_df)} user features to {features_path}")
    
    # Stats
    stats = {
        'total_rows_processed': total_rows,
        'unique_users': len(user_total),
        'unique_domains': len(domain_counts),
        'shadow_ai_visits': category_counts.get('Shadow AI', 0),
        'job_site_visits': category_counts.get('Job Sites', 0),
        'cloud_storage_visits': category_counts.get('Cloud Storage', 0),
        'suspicious_visits': category_counts.get('Suspicious', 0),
    }
    stats_df = pd.DataFrame(list(stats.items()), columns=['Metric', 'Value'])
    stats_df.to_csv(os.path.join(output_dir, 'http_stats.csv'), index=False)
    
    print("[EDA-HTTP] ✓ Analysis complete!")
    for k, v in stats.items():
        print(f"  {k}: {v}")
    
    return user_http_df


def run(data_dir: str, output_dir: str) -> pd.DataFrame:
    """Main entry point for HTTP EDA."""
    http_path = os.path.join(data_dir, 'http.csv')
    out_path = os.path.join(output_dir, 'http')
    features = analyze_http_chunked(http_path, out_path)
    return features


if __name__ == '__main__':
    DATA_DIR = os.path.join(os.path.dirname(__file__), '..', 'Models', 'Data set', 'r4.2')
    OUTPUT_DIR = os.path.join(os.path.dirname(__file__), 'outputs')
    run(DATA_DIR, OUTPUT_DIR)
