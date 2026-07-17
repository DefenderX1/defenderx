"""
DefendX AI Model Training
Trains Isolation Forest (unsupervised anomaly detection) and Random Forest
(supervised classification) models on the engineered feature matrix.
Saves trained models to the Models/ directory.
"""

import pandas as pd
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import (classification_report, confusion_matrix,
                             roc_auc_score, precision_recall_curve,
                             roc_curve, f1_score)
import joblib
import os
import json
import time
import warnings
warnings.filterwarnings('ignore')


PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.join(PROJECT_ROOT, 'Models')
EDA_DIR = os.path.join(PROJECT_ROOT, 'EDA', 'outputs')


def load_feature_matrix(path: str = None) -> pd.DataFrame:
    """Load the engineered feature matrix."""
    if path is None:
        path = os.path.join(MODELS_DIR, 'feature_matrix.csv')
    
    print(f"[Training] Loading feature matrix from {path}...")
    df = pd.read_csv(path)
    print(f"[Training] Loaded {len(df)} users × {len(df.columns)} features")
    return df


def prepare_features(df: pd.DataFrame) -> tuple:
    """Prepare feature matrix for model training."""
    print("[Training] Preparing features...")
    
    # Identify feature columns (exclude identifiers and string columns)
    exclude_cols = ['user', 'employee_name', 'email', 'role', 'business_unit',
                    'functional_unit', 'department', 'team']
    
    feature_cols = [c for c in df.columns if c not in exclude_cols
                    and df[c].dtype in [np.float64, np.int64, float, int]]
    
    print(f"  Using {len(feature_cols)} numeric features:")
    for col in feature_cols:
        print(f"    {col}")
    
    X = df[feature_cols].copy()
    X = X.fillna(0)
    
    # Replace infinities
    X = X.replace([np.inf, -np.inf], 0)
    
    return X, feature_cols


def train_isolation_forest(X: pd.DataFrame, scaler: StandardScaler,
                           contamination: float = 0.05) -> tuple:
    """
    Train Isolation Forest for unsupervised anomaly detection.
    
    Contamination parameter represents the expected proportion of insiders.
    CERT r4.2 has ~1-5% insider threats.
    """
    print(f"\n[Training] Training Isolation Forest (contamination={contamination})...")
    
    X_scaled = scaler.transform(X)
    
    model = IsolationForest(
        n_estimators=200,
        max_samples='auto',
        contamination=contamination,
        max_features=1.0,
        random_state=42,
        n_jobs=-1,
        verbose=0,
    )
    
    t = time.time()
    model.fit(X_scaled)
    train_time = time.time() - t
    
    # Get anomaly scores (-1 for anomalies, 1 for normal)
    predictions = model.predict(X_scaled)
    scores = model.decision_function(X_scaled)
    
    n_anomalies = (predictions == -1).sum()
    n_normal = (predictions == 1).sum()
    
    print(f"  Training time: {train_time:.2f}s")
    print(f"  Normal: {n_normal} ({n_normal/len(X)*100:.1f}%)")
    print(f"  Anomalies: {n_anomalies} ({n_anomalies/len(X)*100:.1f}%)")
    
    return model, predictions, scores


def train_random_forest(X: pd.DataFrame, labels: np.ndarray,
                        scaler: StandardScaler) -> tuple:
    """
    Train Random Forest classifier using Isolation Forest labels
    as pseudo-ground-truth for supervised learning.
    """
    print("\n[Training] Training Random Forest classifier...")
    
    X_scaled = scaler.transform(X)
    
    # Convert IF labels: -1 (anomaly) -> 1 (threat), 1 (normal) -> 0 (safe)
    y = (labels == -1).astype(int)
    
    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, y, test_size=0.2, random_state=42, stratify=y
    )
    
    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=15,
        min_samples_split=5,
        min_samples_leaf=2,
        class_weight='balanced',
        random_state=42,
        n_jobs=-1,
    )
    
    t = time.time()
    model.fit(X_train, y_train)
    train_time = time.time() - t
    
    # Evaluate
    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]
    
    print(f"  Training time: {train_time:.2f}s")
    print(f"  Test set size: {len(X_test)}")
    print("\n  Classification Report:")
    print(classification_report(y_test, y_pred, target_names=['Normal', 'Threat']))
    
    # ROC AUC
    try:
        auc = roc_auc_score(y_test, y_prob)
        print(f"  ROC AUC: {auc:.4f}")
    except Exception:
        auc = 0.0
    
    return model, X_test, y_test, y_pred, y_prob, auc


def generate_training_plots(X: pd.DataFrame, feature_cols: list,
                           if_scores: np.ndarray, if_predictions: np.ndarray,
                           rf_model, y_test, y_prob, output_dir: str):
    """Generate model training visualizations."""
    os.makedirs(output_dir, exist_ok=True)
    
    # ── 1. Anomaly Score Distribution ──
    print("[Training] Generating visualizations...")
    fig, axes = plt.subplots(1, 2, figsize=(16, 6))
    fig.patch.set_facecolor('#0d1117')
    
    ax = axes[0]
    ax.set_facecolor('#161b22')
    normal_scores = if_scores[if_predictions == 1]
    anomaly_scores = if_scores[if_predictions == -1]
    ax.hist(normal_scores, bins=40, color='#10b981', alpha=0.7, label='Normal', edgecolor='none')
    ax.hist(anomaly_scores, bins=40, color='#ff4444', alpha=0.7, label='Anomaly', edgecolor='none')
    ax.set_xlabel('Anomaly Score', color='white', fontsize=11)
    ax.set_ylabel('Count', color='white', fontsize=11)
    ax.set_title('Isolation Forest Anomaly Score Distribution', color='#00d4ff',
                fontsize=14, fontweight='bold')
    ax.legend(facecolor='#161b22', edgecolor='#30363d', labelcolor='white')
    ax.tick_params(colors='white')
    ax.spines['bottom'].set_color('#30363d')
    ax.spines['left'].set_color('#30363d')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    
    # Feature importance
    ax = axes[1]
    ax.set_facecolor('#161b22')
    importances = rf_model.feature_importances_
    indices = np.argsort(importances)[-15:]  # Top 15
    ax.barh([feature_cols[i] for i in indices], importances[indices],
            color='#a855f7', edgecolor='none', alpha=0.85)
    ax.set_xlabel('Importance', color='white', fontsize=11)
    ax.set_title('Top 15 Feature Importances (Random Forest)', color='#a855f7',
                fontsize=14, fontweight='bold')
    ax.tick_params(colors='white', labelsize=8)
    ax.spines['bottom'].set_color('#30363d')
    ax.spines['left'].set_color('#30363d')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'model_training_overview.png'), dpi=150,
                bbox_inches='tight', facecolor='#0d1117', edgecolor='none')
    plt.close()
    
    # ── 2. ROC Curve ──
    try:
        fig, axes = plt.subplots(1, 2, figsize=(16, 6))
        fig.patch.set_facecolor('#0d1117')
        
        ax = axes[0]
        ax.set_facecolor('#161b22')
        fpr, tpr, _ = roc_curve(y_test, y_prob)
        auc_score = roc_auc_score(y_test, y_prob)
        ax.plot(fpr, tpr, color='#00d4ff', linewidth=2, label=f'AUC = {auc_score:.4f}')
        ax.plot([0, 1], [0, 1], 'r--', alpha=0.5, linewidth=1)
        ax.fill_between(fpr, tpr, alpha=0.1, color='#00d4ff')
        ax.set_xlabel('False Positive Rate', color='white', fontsize=11)
        ax.set_ylabel('True Positive Rate', color='white', fontsize=11)
        ax.set_title('ROC Curve', color='#00d4ff', fontsize=14, fontweight='bold')
        ax.legend(facecolor='#161b22', edgecolor='#30363d', labelcolor='white', fontsize=12)
        ax.tick_params(colors='white')
        ax.spines['bottom'].set_color('#30363d')
        ax.spines['left'].set_color('#30363d')
        ax.spines['top'].set_visible(False)
        ax.spines['right'].set_visible(False)
        
        # Confusion matrix
        ax = axes[1]
        ax.set_facecolor('#161b22')
        y_pred_test = rf_model.predict(StandardScaler().fit_transform(
            pd.DataFrame(np.zeros((len(y_test), len(feature_cols))))))  # placeholder
        # Use the actual predictions from test
        cm = confusion_matrix(y_test, (y_prob >= 0.5).astype(int))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', ax=ax,
                    xticklabels=['Normal', 'Threat'], yticklabels=['Normal', 'Threat'],
                    linewidths=1, linecolor='#30363d')
        ax.set_xlabel('Predicted', color='white', fontsize=11)
        ax.set_ylabel('Actual', color='white', fontsize=11)
        ax.set_title('Confusion Matrix', color='#00d4ff', fontsize=14, fontweight='bold')
        ax.tick_params(colors='white')
        
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, 'model_roc_confusion.png'), dpi=150,
                    bbox_inches='tight', facecolor='#0d1117', edgecolor='none')
        plt.close()
    except Exception as e:
        print(f"  ⚠ Could not generate ROC/confusion plots: {e}")
    
    # ── 3. Threat Score Distribution (Final) ──
    fig, ax = plt.subplots(figsize=(12, 6))
    fig.patch.set_facecolor('#0d1117')
    ax.set_facecolor('#161b22')
    
    # Convert IF scores to 0-100 threat scale
    threat_scores = 100 * (1 - (if_scores - if_scores.min()) / (if_scores.max() - if_scores.min()))
    
    ax.hist(threat_scores, bins=50, color='#00d4ff', edgecolor='#161b22', alpha=0.85)
    ax.axvline(np.percentile(threat_scores, 95), color='#ff4444', linestyle='--',
               linewidth=2, label=f'95th Percentile ({np.percentile(threat_scores, 95):.1f})')
    ax.axvline(np.percentile(threat_scores, 99), color='#ff0000', linestyle='-',
               linewidth=2, label=f'99th Percentile ({np.percentile(threat_scores, 99):.1f})')
    ax.set_xlabel('Threat Score (0-100)', color='white', fontsize=11)
    ax.set_ylabel('Users', color='white', fontsize=11)
    ax.set_title('DefendX Threat Score Distribution', color='#00d4ff',
                fontsize=14, fontweight='bold')
    ax.legend(facecolor='#161b22', edgecolor='#30363d', labelcolor='white')
    ax.tick_params(colors='white')
    ax.spines['bottom'].set_color('#30363d')
    ax.spines['left'].set_color('#30363d')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'threat_score_distribution.png'), dpi=150,
                bbox_inches='tight', facecolor='#0d1117', edgecolor='none')
    plt.close()
    
    print("[Training] ✓ Visualizations saved")


def run_training():
    """Main training pipeline."""
    print("=" * 70)
    print("  DefendX — AI Model Training Pipeline")
    print("=" * 70)
    
    start_time = time.time()
    
    # 1. Load feature matrix
    df = load_feature_matrix()
    
    # 2. Prepare features
    X, feature_cols = prepare_features(df)
    
    if len(X) == 0 or len(feature_cols) == 0:
        print("✗ No features available for training!")
        return
    
    # 3. Fit scaler
    print("\n[Training] Fitting StandardScaler...")
    scaler = StandardScaler()
    scaler.fit(X)
    
    # 4. Train Isolation Forest
    if_model, if_predictions, if_scores = train_isolation_forest(X, scaler)
    
    # 5. Train Random Forest
    rf_model, X_test, y_test, y_pred, y_prob, auc = train_random_forest(
        X, if_predictions, scaler
    )
    
    # 6. Generate visualizations
    plots_dir = os.path.join(MODELS_DIR, 'training_plots')
    generate_training_plots(X, feature_cols, if_scores, if_predictions,
                           rf_model, y_test, y_prob, plots_dir)
    
    # 7. Compute final threat scores for all users
    print("\n[Training] Computing final threat scores...")
    threat_scores = 100 * (1 - (if_scores - if_scores.min()) / 
                           (if_scores.max() - if_scores.min()))
    
    X_scaled = scaler.transform(X)
    rf_probs = rf_model.predict_proba(X_scaled)[:, 1]
    
    # Blend scores: 60% IF + 40% RF
    blended_scores = 0.6 * threat_scores + 0.4 * (rf_probs * 100)
    
    df['threat_score'] = blended_scores
    df['threat_level'] = pd.cut(blended_scores,
                                bins=[0, 25, 50, 75, 100],
                                labels=['Low', 'Medium', 'High', 'Critical'])
    df['is_anomaly'] = (if_predictions == -1).astype(int)
    df['if_score'] = if_scores
    df['rf_probability'] = rf_probs
    
    # 8. Save models
    print("\n[Training] Saving models...")
    
    joblib.dump(if_model, os.path.join(MODELS_DIR, 'isolation_forest.pkl'))
    print(f"  ✓ Isolation Forest → Models/isolation_forest.pkl")
    
    joblib.dump(rf_model, os.path.join(MODELS_DIR, 'random_forest.pkl'))
    print(f"  ✓ Random Forest → Models/random_forest.pkl")
    
    joblib.dump(scaler, os.path.join(MODELS_DIR, 'scaler.pkl'))
    print(f"  ✓ Scaler → Models/scaler.pkl")
    
    # Save feature columns for inference
    model_config = {
        'feature_columns': feature_cols,
        'contamination': 0.05,
        'if_threshold': float(np.percentile(if_scores, 5)),
        'threat_score_thresholds': {
            'low': 25, 'medium': 50, 'high': 75, 'critical': 90
        },
        'training_samples': len(X),
        'n_features': len(feature_cols),
        'auc_score': float(auc),
    }
    
    config_path = os.path.join(MODELS_DIR, 'model_config.json')
    with open(config_path, 'w') as f:
        json.dump(model_config, f, indent=2)
    print(f"  ✓ Config → Models/model_config.json")
    
    # Save scored results
    results_path = os.path.join(MODELS_DIR, 'threat_scores.csv')
    df.to_csv(results_path, index=False)
    print(f"  ✓ Threat Scores → Models/threat_scores.csv")
    
    # ── Summary ──
    total_time = time.time() - start_time
    print("\n" + "=" * 70)
    print(f"  Training Complete! Total time: {total_time:.1f}s")
    print("=" * 70)
    
    # Top threats
    print("\n  🚨 Top 10 Highest-Risk Users:")
    top_threats = df.nlargest(10, 'threat_score')[['user', 'threat_score', 'threat_level']]
    for _, row in top_threats.iterrows():
        level_icon = {'Critical': '🔴', 'High': '🟠', 'Medium': '🟡', 'Low': '🟢'}
        icon = level_icon.get(row['threat_level'], '⚪')
        print(f"    {icon} {row['user']}: {row['threat_score']:.1f} ({row['threat_level']})")
    
    print(f"\n  Threat Distribution:")
    for level in ['Critical', 'High', 'Medium', 'Low']:
        count = (df['threat_level'] == level).sum()
        print(f"    {level}: {count} users ({count/len(df)*100:.1f}%)")
    
    return df


if __name__ == '__main__':
    run_training()
