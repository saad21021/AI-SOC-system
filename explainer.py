import shap
import joblib
import numpy as np
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

random_forest = joblib.load(os.path.join(BASE_DIR, 'random_forest.pkl'))
scaler = joblib.load(os.path.join(BASE_DIR, 'scaler.pkl'))

FEATURE_COLUMNS = scaler.feature_names_in_

# Faster + stable explainer
explainer = shap.TreeExplainer(
    random_forest,
    feature_perturbation="tree_path_dependent"
)

def get_shap_explanation(X_scaled_packet, predicted_cluster):
    if len(X_scaled_packet.shape) == 1:
        X_scaled_packet = X_scaled_packet.reshape(1, -1)

    shap_values = explainer.shap_values(X_scaled_packet)

    # Handle multiclass cleanly
    if isinstance(shap_values, list):
        class_idx = list(random_forest.classes_).index(predicted_cluster)
        packet_shap_values = shap_values[class_idx][0]
    elif hasattr(shap_values, 'values'):
        packet_shap_values = shap_values.values[0]
    else:
        if len(shap_values.shape) == 3:
            class_idx = list(random_forest.classes_).index(predicted_cluster)
            packet_shap_values = shap_values[0, :, class_idx]
        else:
            packet_shap_values = shap_values[0]

    feature_impacts = list(zip(FEATURE_COLUMNS, packet_shap_values))

    # Sort by importance
    feature_impacts.sort(key=lambda x: abs(x[1]), reverse=True)

    top_features = []
    for feat, impact in feature_impacts[:5]:
        top_features.append({
            "feature": feat,
            "impact": float(impact),
            "direction": "increase" if impact > 0 else "decrease",
            "explanation": f"{feat} influenced the model decision"
        })

    return top_features
