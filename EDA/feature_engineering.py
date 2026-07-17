"""
Feature Engineering Module
Combines features from all EDA modules into a unified per-user
behavioral feature matrix for AI model training.
"""

import pandas as pd
import numpy as np
import os
import warnings
warnings.filterwarnings('ignore')


def build_feature_matrix(eda_output_dir: str, model_output_dir: str) -> pd.DataFrame:
    """
    Merge all per-user features from EDA modules into a single feature matrix.
    
    Expected feature files in eda_output_dir:
    - logon/logon_features.csv
    - device/device_features.csv
    - file/file_features.csv
    - http/http_features.csv
    - psychometric/psychometric_features.csv
    - ldap/ldap_features.csv
    """
    print("[Feature Engineering] Building unified feature matrix...")
    
    # ── Load all feature files ──
    features = {}
    
    # 1. Logon features
    logon_path = os.path.join(eda_output_dir, 'logon', 'logon_features.csv')
    if os.path.exists(logon_path):
        features['logon'] = pd.read_csv(logon_path)
        print(f"  Logon features: {len(features['logon'])} users, {len(features['logon'].columns)} cols")
    else:
        print("  ⚠ Logon features not found")
    
    # 2. Device features
    device_path = os.path.join(eda_output_dir, 'device', 'device_features.csv')
    if os.path.exists(device_path):
        features['device'] = pd.read_csv(device_path)
        print(f"  Device features: {len(features['device'])} users, {len(features['device'].columns)} cols")
    else:
        print("  ⚠ Device features not found")
    
    # 3. File features
    file_path = os.path.join(eda_output_dir, 'file', 'file_features.csv')
    if os.path.exists(file_path):
        features['file'] = pd.read_csv(file_path)
        print(f"  File features: {len(features['file'])} users, {len(features['file'].columns)} cols")
    else:
        print("  ⚠ File features not found")
    
    # 4. HTTP features
    http_path = os.path.join(eda_output_dir, 'http', 'http_features.csv')
    if os.path.exists(http_path):
        features['http'] = pd.read_csv(http_path)
        print(f"  HTTP features: {len(features['http'])} users, {len(features['http'].columns)} cols")
    else:
        print("  ⚠ HTTP features not found")
    
    # 5. Psychometric features
    psych_path = os.path.join(eda_output_dir, 'psychometric', 'psychometric_features.csv')
    if os.path.exists(psych_path):
        features['psychometric'] = pd.read_csv(psych_path)
        print(f"  Psychometric features: {len(features['psychometric'])} users, {len(features['psychometric'].columns)} cols")
    else:
        print("  ⚠ Psychometric features not found")
    
    # 6. LDAP features
    ldap_path = os.path.join(eda_output_dir, 'ldap', 'ldap_features.csv')
    if os.path.exists(ldap_path):
        features['ldap'] = pd.read_csv(ldap_path)
        print(f"  LDAP features: {len(features['ldap'])} users, {len(features['ldap'].columns)} cols")
    else:
        print("  ⚠ LDAP features not found")
    
    if not features:
        print("  ✗ No feature files found! Run EDA pipeline first.")
        return pd.DataFrame()
    
    # ── Merge all features ──
    print("[Feature Engineering] Merging features...")
    
    # Start with psychometric (has all 1000 users) or LDAP as base
    if 'psychometric' in features:
        merged = features['psychometric'].copy()
    elif 'ldap' in features:
        merged = features['ldap'][['user']].copy()
    else:
        # Use the first available feature set
        first_key = list(features.keys())[0]
        merged = features[first_key][['user']].drop_duplicates().copy()
    
    # Left-join all other features
    for name, df in features.items():
        if name == 'psychometric':
            continue  # Already base
        merged = merged.merge(df, on='user', how='left')
    
    # ── Handle categorical features ──
    print("[Feature Engineering] Encoding categorical features...")
    categorical_cols = ['role', 'business_unit', 'functional_unit', 'department', 'team']
    label_mappings = {}
    
    for col in categorical_cols:
        if col in merged.columns:
            merged[col] = merged[col].fillna('Unknown')
            unique_vals = merged[col].unique()
            mapping = {val: idx for idx, val in enumerate(unique_vals)}
            label_mappings[col] = mapping
            merged[f'{col}_encoded'] = merged[col].map(mapping)
    
    # ── Fill missing numerical values ──
    numerical_cols = merged.select_dtypes(include=[np.number]).columns
    merged[numerical_cols] = merged[numerical_cols].fillna(0)
    
    # ── Compute composite threat indicators ──
    print("[Feature Engineering] Computing composite threat indicators...")
    
    # Data Exfiltration Risk Score
    exfil_cols = []
    if 'file_copy_after_hours' in merged.columns:
        exfil_cols.append('file_copy_after_hours')
    if 'usb_after_hours' in merged.columns:
        exfil_cols.append('usb_after_hours')
    if 'http_cloud_storage' in merged.columns:
        exfil_cols.append('http_cloud_storage')
    
    if exfil_cols:
        for col in exfil_cols:
            col_max = merged[col].max()
            if col_max > 0:
                merged[f'{col}_norm'] = merged[col] / col_max
            else:
                merged[f'{col}_norm'] = 0
        
        norm_cols = [f'{c}_norm' for c in exfil_cols]
        merged['exfiltration_risk'] = merged[norm_cols].mean(axis=1) * 100
        merged.drop(columns=norm_cols, inplace=True)
    
    # Shadow AI Risk Score
    if 'http_shadow_ai' in merged.columns:
        max_ai = merged['http_shadow_ai'].max()
        if max_ai > 0:
            merged['shadow_ai_risk'] = merged['http_shadow_ai'] / max_ai * 100
        else:
            merged['shadow_ai_risk'] = 0
    
    # Flight Risk (job site visits + departure)
    if 'http_job_sites' in merged.columns:
        max_jobs = merged['http_job_sites'].max()
        if max_jobs > 0:
            merged['flight_risk'] = merged['http_job_sites'] / max_jobs * 50
        else:
            merged['flight_risk'] = 0
        if 'left_company' in merged.columns:
            merged['flight_risk'] += merged['left_company'] * 50
    
    # Overall Behavioral Anomaly Score (composite)
    risk_cols = [c for c in ['exfiltration_risk', 'shadow_ai_risk', 'flight_risk',
                             'risk_score_personality', 'after_hours_ratio',
                             'file_after_hours_ratio', 'usb_after_hours_ratio'] 
                 if c in merged.columns]
    
    if risk_cols:
        for col in risk_cols:
            col_max = merged[col].max()
            if col_max > 0:
                merged[f'{col}_n'] = merged[col] / col_max
            else:
                merged[f'{col}_n'] = 0
        norm_risk = [f'{c}_n' for c in risk_cols]
        merged['composite_risk_score'] = merged[norm_risk].mean(axis=1) * 100
        merged.drop(columns=norm_risk, inplace=True)
    
    # ── Save feature matrix ──
    os.makedirs(model_output_dir, exist_ok=True)
    output_path = os.path.join(model_output_dir, 'feature_matrix.csv')
    merged.to_csv(output_path, index=False)
    
    print(f"\n[Feature Engineering] ✓ Feature matrix built!")
    print(f"  Users: {len(merged)}")
    print(f"  Features: {len(merged.columns)}")
    print(f"  Saved to: {output_path}")
    
    # Print feature summary
    print("\n  Feature columns:")
    for col in merged.columns:
        dtype = merged[col].dtype
        if dtype in [np.float64, np.int64, float, int]:
            print(f"    {col}: {dtype} (range: {merged[col].min():.2f} — {merged[col].max():.2f})")
        else:
            print(f"    {col}: {dtype} ({merged[col].nunique()} unique)")
    
    # Save label mappings for later use
    if label_mappings:
        import json
        # Convert numpy int64 values to native Python int for JSON serialization
        serializable_mappings = {}
        for col, mapping in label_mappings.items():
            serializable_mappings[col] = {str(k): int(v) for k, v in mapping.items()}
        mappings_path = os.path.join(model_output_dir, 'label_mappings.json')
        with open(mappings_path, 'w') as f:
            json.dump(serializable_mappings, f, indent=2)
        print(f"  Label mappings saved to: {mappings_path}")
    
    return merged


def run(eda_output_dir: str, model_output_dir: str) -> pd.DataFrame:
    """Main entry point."""
    return build_feature_matrix(eda_output_dir, model_output_dir)


if __name__ == '__main__':
    base = os.path.dirname(__file__)
    EDA_OUTPUT = os.path.join(base, 'outputs')
    MODEL_OUTPUT = os.path.join(base, '..', 'Models')
    run(EDA_OUTPUT, MODEL_OUTPUT)
