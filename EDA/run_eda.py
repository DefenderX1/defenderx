"""
Master EDA Runner
Orchestrates the full EDA pipeline across all dataset modules.
Generates visualizations, statistics, and feature files for model training.
"""

import os
import sys
import time

# Add project root to path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from EDA import eda_logon, eda_device, eda_file, eda_http, eda_psychometric, eda_ldap
from EDA import feature_engineering


def run_full_eda(data_dir: str = None, output_dir: str = None, skip_http: bool = False):
    """
    Run the complete EDA pipeline.
    
    Args:
        data_dir: Path to the r4.2 dataset directory
        output_dir: Path to save EDA outputs
        skip_http: If True, skip the massive HTTP file analysis
    """
    if data_dir is None:
        data_dir = os.path.join(PROJECT_ROOT, 'Models', 'Data set', 'r4.2')
    if output_dir is None:
        output_dir = os.path.join(PROJECT_ROOT, 'EDA', 'outputs')
    
    model_dir = os.path.join(PROJECT_ROOT, 'Models')
    
    print("=" * 70)
    print("  DefendX — Exploratory Data Analysis Pipeline")
    print("  CERT r4.2 Insider Threat Dataset")
    print("=" * 70)
    print(f"  Data Directory: {data_dir}")
    print(f"  Output Directory: {output_dir}")
    print(f"  Skip HTTP: {skip_http}")
    print("=" * 70)
    
    os.makedirs(output_dir, exist_ok=True)
    start_time = time.time()
    
    # ── Phase 1: Individual Dataset Analysis ──
    print("\n" + "─" * 50)
    print("Phase 1: Individual Dataset Analysis")
    print("─" * 50)
    
    # 1. Logon Analysis
    print("\n[1/6] Logon Activity Analysis")
    t = time.time()
    try:
        eda_logon.run(data_dir, output_dir)
        print(f"  ⏱ Completed in {time.time() - t:.1f}s")
    except Exception as e:
        print(f"  ✗ Error: {e}")
    
    # 2. Device Analysis
    print("\n[2/6] USB Device Analysis")
    t = time.time()
    try:
        eda_device.run(data_dir, output_dir)
        print(f"  ⏱ Completed in {time.time() - t:.1f}s")
    except Exception as e:
        print(f"  ✗ Error: {e}")
    
    # 3. File Analysis
    print("\n[3/6] File Transfer Analysis")
    t = time.time()
    try:
        eda_file.run(data_dir, output_dir)
        print(f"  ⏱ Completed in {time.time() - t:.1f}s")
    except Exception as e:
        print(f"  ✗ Error: {e}")
    
    # 4. HTTP Analysis (optional — very large file)
    print("\n[4/6] HTTP Activity Analysis")
    if skip_http:
        print("  ⏭ Skipped (--skip-http flag)")
    else:
        t = time.time()
        try:
            eda_http.run(data_dir, output_dir)
            print(f"  ⏱ Completed in {time.time() - t:.1f}s")
        except Exception as e:
            print(f"  ✗ Error: {e}")
    
    # 5. Psychometric Analysis
    print("\n[5/6] Psychometric Analysis")
    t = time.time()
    try:
        eda_psychometric.run(data_dir, output_dir)
        print(f"  ⏱ Completed in {time.time() - t:.1f}s")
    except Exception as e:
        print(f"  ✗ Error: {e}")
    
    # 6. LDAP Analysis
    print("\n[6/6] LDAP / Organizational Analysis")
    t = time.time()
    try:
        eda_ldap.run(data_dir, output_dir)
        print(f"  ⏱ Completed in {time.time() - t:.1f}s")
    except Exception as e:
        print(f"  ✗ Error: {e}")
    
    # ── Phase 2: Feature Engineering ──
    print("\n" + "─" * 50)
    print("Phase 2: Feature Engineering")
    print("─" * 50)
    
    t = time.time()
    try:
        feature_matrix = feature_engineering.run(output_dir, model_dir)
        print(f"  ⏱ Completed in {time.time() - t:.1f}s")
    except Exception as e:
        print(f"  ✗ Error: {e}")
        feature_matrix = None
    
    # ── Summary ──
    total_time = time.time() - start_time
    print("\n" + "=" * 70)
    print(f"  EDA Pipeline Complete! Total time: {total_time:.1f}s ({total_time/60:.1f} min)")
    print("=" * 70)
    
    # List generated outputs
    print("\n  Generated outputs:")
    for root, dirs, files in os.walk(output_dir):
        for f in files:
            fpath = os.path.join(root, f)
            size = os.path.getsize(fpath)
            rel = os.path.relpath(fpath, output_dir)
            print(f"    {rel} ({size:,} bytes)")
    
    if feature_matrix is not None:
        fm_path = os.path.join(model_dir, 'feature_matrix.csv')
        if os.path.exists(fm_path):
            print(f"\n  Feature matrix: {fm_path} ({os.path.getsize(fm_path):,} bytes)")
    
    return feature_matrix


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='DefendX EDA Pipeline')
    parser.add_argument('--data-dir', type=str, default=None, help='Path to r4.2 dataset')
    parser.add_argument('--output-dir', type=str, default=None, help='Path to save outputs')
    parser.add_argument('--skip-http', action='store_true', help='Skip HTTP analysis (14.5GB)')
    args = parser.parse_args()
    
    run_full_eda(args.data_dir, args.output_dir, args.skip_http)
