import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib

# Load and clean column names
df = pd.read_csv("top_features_portscan.csv")
df.columns = df.columns.str.strip()  # Clean up spaces in column names

# Drop rows with any NaN or inf values (safest and easiest way)
df = df.replace([float('inf'), float('-inf')], pd.NA)  # Replace inf with NA
df = df.dropna()  # Drop all rows with any NA

# Ensure that 'Label' exists and is accessed correctly
if 'Label' not in df.columns:
    print("Error: 'Label' column not found.")
else:
    # Encode target: 1 for portscan, 0 for normal traffic (BENIGN)
    df['Label'] = df['Label'].apply(lambda x: 1 if x == 'PortScan' else 0)

    # Separate features and target
    X = df.drop(columns=['Label'])
    y = df['Label']

    # Combine for balancing
    df_balanced = pd.concat([X, y], axis=1)

    # Split into classes
    df_normal = df_balanced[df_balanced['Label'] == 0]
    df_portscan = df_balanced[df_balanced['Label'] == 1]

    # Check if df_portscan is empty
    if df_portscan.empty:
        print("⚠️ Warning: No portscan data found in the dataset.")
        # In this case, you can either skip balancing or handle it in another way
        df_normal_downsampled = df_normal  # No downsampling
    else:
        # Check if df_normal is smaller than df_portscan
        if len(df_normal) < len(df_portscan):
            print(
                f"⚠️ Normal traffic has fewer samples than portscan, skipping downsampling.")
            df_normal_downsampled = df_normal  # No downsampling
        else:
            # Downsample the majority class (normal traffic) to match the number of portscan samples
            df_normal_downsampled = df_normal.sample(
                n=len(df_portscan), random_state=42)

    # Combine to make a balanced dataset
    df_balanced = pd.concat([df_normal_downsampled, df_portscan])

    # Shuffle the dataset
    df_balanced = df_balanced.sample(
        frac=1, random_state=42).reset_index(drop=True)

    # Now extract final X and y
    X = df_balanced.drop(columns=['Label'])
    y = df_balanced['Label']

    # Scale features
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # Train/test split and model training
    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, y, test_size=0.2, random_state=42)
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)

    # Evaluate
    y_pred = model.predict(X_test)
    print("Classification Report:\n", classification_report(y_test, y_pred))

    # Save model and scaler
    joblib.dump(model, "model.pkl")
    joblib.dump(scaler, "scaler.pkl")
    print("✅ Model and scaler saved!")

    # Final class distribution after balancing
    print("✅ Final training class distribution:")
    print(y.value_counts())
