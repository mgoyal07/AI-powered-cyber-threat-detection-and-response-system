import pandas as pd
import numpy as np
import os

# Create dataset directory if not present
os.makedirs("dataset", exist_ok=True)

# Top 3 features from DoS Hulk importance file
top_features = ['Init_Win_bytes_forward', ' Destination Port', ' Subflow Bwd Bytes']

# Generate BENIGN samples
np.random.seed(42)
benign_data = {
    'Init_Win_bytes_forward': np.random.normal(loc=1000, scale=100, size=100),
    ' Destination Port': np.random.randint(1024, 65535, size=100),
    ' Subflow Bwd Bytes': np.random.normal(loc=5000, scale=500, size=100),
    ' Label': ['BENIGN'] * 100
}

# Generate CustomAttack samples
attack_data = {
    'Init_Win_bytes_forward': np.random.normal(loc=30000, scale=1000, size=100),
    ' Destination Port': np.random.randint(1, 1024, size=100),
    ' Subflow Bwd Bytes': np.random.normal(loc=20000, scale=2000, size=100),
    ' Label': ['CustomAttack'] * 100
}

# Combine and shuffle
df_benign = pd.DataFrame(benign_data)
df_attack = pd.DataFrame(attack_data)
df_combined = pd.concat([df_benign, df_attack], ignore_index=True)
df_combined = df_combined.sample(frac=1, random_state=42).reset_index(drop=True)

# Save to CSV
dataset_path = "dataset/CustomAttack_vs_BENIGN.csv"
df_combined.to_csv(dataset_path, index=False)
print(f"✅ Created {dataset_path} with 200 rows.")

# Create importance file
importance_data = {
    'Feature': top_features,
    'Weight': [0.35, 0.33, 0.32]
}
df_importance = pd.DataFrame(importance_data)
importance_path = "dataset/CustomAttack_importance.csv"
df_importance.to_csv(importance_path, index=False)
print(f"✅ Created {importance_path}")
