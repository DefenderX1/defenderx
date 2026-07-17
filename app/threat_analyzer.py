"""
DefendX — Threat Analysis Engine
Loads trained AI models and scores users for insider threat risk.
Provides explainable threat breakdowns.
"""

import pandas as pd
import numpy as np
import joblib
import json
import os

class ThreatAnalyzer:
    """
    Loads trained ML models and scores users for insider threat risk.
    Supports both batch scoring and individual user analysis.
    """
    
    def __init__(self, models_dir: str):
        self.models_dir = models_dir
        self.if_model = None
        self.rf_model = None
        self.scaler = None
        self.config = None
        self.feature_cols = []
        self.threat_scores_df = None
        self.feature_matrix_df = None
        self._loaded = False
    
    def load_models(self) -> bool:
        """Load all trained models and configuration."""
        try:
            # Load Isolation Forest
            if_path = os.path.join(self.models_dir, 'isolation_forest.pkl')
            if os.path.exists(if_path):
                self.if_model = joblib.load(if_path)
                print("[ThreatAnalyzer] ✓ Isolation Forest loaded")
            
            # Load Random Forest
            rf_path = os.path.join(self.models_dir, 'random_forest.pkl')
            if os.path.exists(rf_path):
                self.rf_model = joblib.load(rf_path)
                print("[ThreatAnalyzer] ✓ Random Forest loaded")
            
            # Load Scaler
            scaler_path = os.path.join(self.models_dir, 'scaler.pkl')
            if os.path.exists(scaler_path):
                self.scaler = joblib.load(scaler_path)
                print("[ThreatAnalyzer] ✓ Scaler loaded")
            
            # Load config
            config_path = os.path.join(self.models_dir, 'model_config.json')
            if os.path.exists(config_path):
                with open(config_path) as f:
                    self.config = json.load(f)
                self.feature_cols = self.config.get('feature_columns', [])
                print(f"[ThreatAnalyzer] ✓ Config loaded ({len(self.feature_cols)} features)")
            
            # Load pre-computed threat scores
            scores_path = os.path.join(self.models_dir, 'threat_scores.csv')
            if os.path.exists(scores_path):
                self.threat_scores_df = pd.read_csv(scores_path)
                print(f"[ThreatAnalyzer] ✓ Threat scores loaded ({len(self.threat_scores_df)} users)")
            
            # Load feature matrix
            fm_path = os.path.join(self.models_dir, 'feature_matrix.csv')
            if os.path.exists(fm_path):
                self.feature_matrix_df = pd.read_csv(fm_path)
            
            self._loaded = True
            return True
            
        except Exception as e:
            print(f"[ThreatAnalyzer] ✗ Error loading models: {e}")
            return False
    
    @property
    def is_loaded(self) -> bool:
        return self._loaded
    
    def get_all_threat_scores(self) -> pd.DataFrame:
        """Return pre-computed threat scores for all users."""
        if self.threat_scores_df is not None:
            return self.threat_scores_df
        return pd.DataFrame()
    
    def get_top_threats(self, n: int = 10) -> pd.DataFrame:
        """Get top N highest-risk users."""
        if self.threat_scores_df is not None:
            return self.threat_scores_df.nlargest(n, 'threat_score')
        return pd.DataFrame()
    
    def get_user_profile(self, user_id: str) -> dict:
        """Get detailed threat profile for a specific user."""
        if self.threat_scores_df is None:
            return {}
        
        user_row = self.threat_scores_df[self.threat_scores_df['user'] == user_id]
        if len(user_row) == 0:
            return {}
        
        user = user_row.iloc[0]
        profile = {
            'user_id': user_id,
            'threat_score': float(user.get('threat_score', 0)),
            'threat_level': str(user.get('threat_level', 'Unknown')),
            'is_anomaly': bool(user.get('is_anomaly', False)),
        }
        
        # Behavioral metrics
        metrics = {}
        metric_keys = {
            'total_logins': 'Total Logins',
            'after_hours_logins': 'After-Hours Logins',
            'after_hours_ratio': 'After-Hours Login Ratio',
            'unique_pcs': 'Unique PCs Accessed',
            'usb_connects': 'USB Connections',
            'usb_after_hours': 'After-Hours USB',
            'file_copy_count': 'Files Copied (Removable)',
            'file_copy_after_hours': 'After-Hours File Copies',
            'http_total': 'Total Web Requests',
            'http_shadow_ai': 'Shadow AI Visits',
            'http_job_sites': 'Job Site Visits',
            'http_cloud_storage': 'Cloud Storage Visits',
            'http_suspicious': 'Suspicious URL Visits',
            'O': 'Openness',
            'C': 'Conscientiousness',
            'E': 'Extraversion',
            'A': 'Agreeableness',
            'N': 'Neuroticism',
            'left_company': 'Left Company',
        }
        
        for key, label in metric_keys.items():
            if key in user.index:
                val = user[key]
                if pd.notna(val):
                    metrics[label] = float(val) if isinstance(val, (int, float, np.number)) else str(val)
        
        profile['metrics'] = metrics
        
        # Risk factors (what contributes to the score)
        risk_factors = []
        
        if user.get('after_hours_ratio', 0) > 0.1:
            risk_factors.append({
                'factor': 'Excessive After-Hours Logins',
                'severity': 'High' if user['after_hours_ratio'] > 0.2 else 'Medium',
                'detail': f"{user['after_hours_ratio']*100:.1f}% of logins are after-hours"
            })
        
        if user.get('unique_pcs', 0) > 3:
            risk_factors.append({
                'factor': 'Multi-PC Access Pattern',
                'severity': 'Medium',
                'detail': f"Accessed {int(user['unique_pcs'])} different workstations"
            })
        
        if user.get('usb_after_hours', 0) > 5:
            risk_factors.append({
                'factor': 'After-Hours USB Activity',
                'severity': 'High',
                'detail': f"{int(user['usb_after_hours'])} USB connections outside business hours"
            })
        
        if user.get('file_copy_after_hours', 0) > 3:
            risk_factors.append({
                'factor': 'After-Hours Data Transfer',
                'severity': 'Critical',
                'detail': f"{int(user['file_copy_after_hours'])} files copied to removable media after-hours"
            })
        
        if user.get('http_shadow_ai', 0) > 10:
            risk_factors.append({
                'factor': 'Shadow AI Usage Detected',
                'severity': 'High',
                'detail': f"{int(user['http_shadow_ai'])} visits to unauthorized AI platforms"
            })
        
        if user.get('http_job_sites', 0) > 20:
            risk_factors.append({
                'factor': 'Flight Risk — Job Seeking Activity',
                'severity': 'Medium',
                'detail': f"{int(user['http_job_sites'])} visits to job search sites"
            })
        
        if user.get('http_suspicious', 0) > 0:
            risk_factors.append({
                'factor': 'Suspicious Web Activity',
                'severity': 'Critical',
                'detail': f"{int(user['http_suspicious'])} visits to flagged domains"
            })
        
        if user.get('left_company', 0) == 1:
            risk_factors.append({
                'factor': 'Employee Has Left Company',
                'severity': 'Critical',
                'detail': 'No longer appears in organizational records'
            })
        
        profile['risk_factors'] = risk_factors
        
        # Composite scores
        composite = {}
        for key in ['exfiltration_risk', 'shadow_ai_risk', 'flight_risk',
                     'risk_score_personality', 'composite_risk_score']:
            if key in user.index and pd.notna(user[key]):
                composite[key.replace('_', ' ').title()] = float(user[key])
        
        profile['composite_scores'] = composite
        
        return profile
    
    def get_threat_distribution(self) -> dict:
        """Get count of users by threat level."""
        if self.threat_scores_df is None:
            return {}
        
        dist = self.threat_scores_df['threat_level'].value_counts().to_dict()
        return {str(k): int(v) for k, v in dist.items()}
    
    def get_anomaly_stats(self) -> dict:
        """Get anomaly detection statistics."""
        if self.threat_scores_df is None:
            return {}
        
        df = self.threat_scores_df
        return {
            'total_users': len(df),
            'anomalies': int(df['is_anomaly'].sum()) if 'is_anomaly' in df.columns else 0,
            'mean_threat_score': float(df['threat_score'].mean()) if 'threat_score' in df.columns else 0,
            'max_threat_score': float(df['threat_score'].max()) if 'threat_score' in df.columns else 0,
            'critical_count': int((df['threat_level'] == 'Critical').sum()) if 'threat_level' in df.columns else 0,
            'high_count': int((df['threat_level'] == 'High').sum()) if 'threat_level' in df.columns else 0,
        }
    
    def search_users(self, query: str) -> pd.DataFrame:
        """Search users by ID pattern."""
        if self.threat_scores_df is None:
            return pd.DataFrame()
        
        mask = self.threat_scores_df['user'].str.contains(query, case=False, na=False)
        return self.threat_scores_df[mask].sort_values('threat_score', ascending=False)
    
    def score_new_data(self, features_dict: dict) -> dict:
        """Score a single user's features in real-time."""
        if not self._loaded or self.if_model is None:
            return {'error': 'Models not loaded'}
        
        try:
            # Build feature vector
            X = pd.DataFrame([features_dict])
            for col in self.feature_cols:
                if col not in X.columns:
                    X[col] = 0
            X = X[self.feature_cols].fillna(0)
            
            # Scale
            X_scaled = self.scaler.transform(X)
            
            # Score
            if_pred = self.if_model.predict(X_scaled)[0]
            if_score = self.if_model.decision_function(X_scaled)[0]
            
            rf_prob = 0.0
            if self.rf_model is not None:
                rf_prob = self.rf_model.predict_proba(X_scaled)[0][1]
            
            # Convert to 0-100 threat score
            all_scores = self.if_model.decision_function(
                self.scaler.transform(self.feature_matrix_df[self.feature_cols].fillna(0))
            ) if self.feature_matrix_df is not None else np.array([if_score])
            
            threat_score = 100 * (1 - (if_score - all_scores.min()) / 
                                  (all_scores.max() - all_scores.min()))
            blended = 0.6 * threat_score + 0.4 * (rf_prob * 100)
            
            return {
                'threat_score': float(blended),
                'is_anomaly': bool(if_pred == -1),
                'if_raw_score': float(if_score),
                'rf_probability': float(rf_prob),
            }
        except Exception as e:
            return {'error': str(e)}
