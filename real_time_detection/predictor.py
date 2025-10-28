"""
predictor.py

Load preprocessing artifacts and ML models saved with joblib and expose a Predictor
class with a predict_proba(feature_vector) method that returns model probabilities.

Expectations:
- The preferred artifact is 'models/scaler_selected.joblib' (MinMaxScaler fitted on
  the 20 selected features). If present, Predictor will scale the 20-D vector
  directly.
- Models required: 'logistic_regression_model.joblib' and 'decision_tree_model.joblib'.
"""

import os
import joblib
import numpy as np
from typing import List, Dict


class Predictor:
    """
    Load scaler(s) and models from a directory and provide predict().

    Args:
        models_dir: path to directory with joblib files.
    """

    def __init__(self, models_dir: str = 'models'):
        self.models_dir = models_dir
        self.scaler_selected = None  # scaler fitted on the 20 selected features
        self.model_lr = None
        self.model_dt = None

        # Try to load scaler_selected
        scaler_sel_path = os.path.join(models_dir, 'scaler_selected.joblib')
        if os.path.exists(scaler_sel_path):
            self.scaler_selected = joblib.load(scaler_sel_path)

        # Load models (required)
        lr_path = os.path.join(models_dir, 'logistic_regression_model.joblib')
        dt_path = os.path.join(models_dir, 'decision_tree_model.joblib')
        if not os.path.exists(lr_path) or not os.path.exists(dt_path):
            raise FileNotFoundError(f"Required model files not found in {models_dir}. Expected: {lr_path}, {dt_path}")
        self.model_lr = joblib.load(lr_path)
        self.model_dt = joblib.load(dt_path)

    def _preprocess(self, fv: List[float]) -> np.ndarray:
        """
        Preprocess 20-D feature vector for prediction.

        Returns:
            numpy array shaped (1, n_features_expected_by_models)
        """
        x = np.array(fv, dtype=float).reshape(1, -1)
        if self.scaler_selected is not None:
            x_scaled = self.scaler_selected.transform(x)
            return x_scaled
        else:
            # If no scaler_selected is provided, assume raw features are already scaled/compatible.
            # This is less safe — prefer saving scaler_selected during training.
            return x

    def predict(self, fv: List[float], threshold: float = 0.5) -> Dict[str, object]:
        """
        Predict probabilities and labels from both models.

        Args:
            fv: list of 20 floats in the same order as training features.
            threshold: probability threshold to label as malicious.

        Returns:
            dict with keys:
              - 'lr_proba', 'lr_label', 'dt_proba', 'dt_label'
        """
        x_pre = self._preprocess(fv)
        # logistic proba (prob of class 1)
        if hasattr(self.model_lr, 'predict_proba'):
            lr_proba = float(self.model_lr.predict_proba(x_pre)[:, 1][0])
        else:
            # If model does not implement predict_proba, fallback to predict (0/1)
            lr_label_only = int(self.model_lr.predict(x_pre)[0])
            lr_proba = float(lr_label_only)

        if hasattr(self.model_dt, 'predict_proba'):
            dt_proba = float(self.model_dt.predict_proba(x_pre)[:, 1][0])
        else:
            dt_label_only = int(self.model_dt.predict(x_pre)[0])
            dt_proba = float(dt_label_only)

        return {
            'lr_proba': lr_proba,
            'lr_label': int(lr_proba >= threshold),
            'dt_proba': dt_proba,
            'dt_label': int(dt_proba >= threshold)
        }
