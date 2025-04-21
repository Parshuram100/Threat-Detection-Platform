import pickle

# Load the trained anomaly detection model (replace with your actual model file path)
model_filename = "decision_tree_model.pkl"  # Replace this with your actual model file path
with open(model_filename, "rb") as file:
    model = pickle.load(file)

# Check if the model has 'classes_' (for classifiers that have labels)
if hasattr(model, 'classes_'):
    print(f"Model labels (classes): {model.classes_}")

# Check if the model is a tree-based model or has feature importances
if hasattr(model, 'feature_importances_'):
    print(f"Model feature importances: {model.feature_importances_}")
elif hasattr(model, 'coef_'):
    print(f"Model coefficients: {model.coef_}")
else:
    print("Model does not have feature importances or coefficients attribute.")

# For models that don't expose feature_importances_ or coef_, we can assume the features
# used during training are known (e.g., in the case of tabular data).
# Replace the list below with the actual features used during model training.
features = ["Feature_1", "Feature_2", "Feature_3", "Feature_4"]  # Replace with actual features
print(f"Features used in the model: {features}")
