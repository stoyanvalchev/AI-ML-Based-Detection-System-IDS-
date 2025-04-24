# Import necessary libraries
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib

# Load dataset and clean column names (strip extra spaces if present)
df = pd.read_csv("top_features_portscan.csv")
df.columns = df.columns.str.strip()

# Handle infinite values and missing data
# Replace infinities with NA
df = df.replace([float('inf'), float('-inf')], pd.NA)
df = df.dropna()  # Drop rows with any missing values (NaNs)

# Ensure the dataset contains the target column 'Label'
if 'Label' not in df.columns:
    print("Error: 'Label' column not found.")
else:
    # Encode the labels: 'PortScan' as 1 (malicious), everything else as 0 (benign)
    df['Label'] = df['Label'].apply(lambda x: 1 if x == 'PortScan' else 0)

    # Separate features and labels
    X = df.drop(columns=['Label'])
    y = df['Label']

    # Combine features and labels into a single DataFrame for balancing
    df_balanced = pd.concat([X, y], axis=1)

    # Separate the data into two classes
    df_normal = df_balanced[df_balanced['Label'] == 0]       # Benign traffic
    df_portscan = df_balanced[df_balanced['Label'] == 1]     # Portscan attacks

    # Check for presence of portscan samples
    if df_portscan.empty:
        print("⚠️ Warning: No portscan data found in the dataset.")
        df_normal_downsampled = df_normal  # Skip balancing
    else:
        # Check if normal traffic has fewer samples than portscan
        if len(df_normal) < len(df_portscan):
            print(
                "⚠️ Normal traffic has fewer samples than portscan, skipping downsampling.")
            df_normal_downsampled = df_normal
        else:
            # Downsample the normal traffic to match the number of portscan samples
            df_normal_downsampled = df_normal.sample(
                n=len(df_portscan), random_state=42)

    # Combine the downsampled normal data and portscan data to form a balanced dataset
    df_balanced = pd.concat([df_normal_downsampled, df_portscan])

    # Shuffle the balanced dataset
    df_balanced = df_balanced.sample(
        frac=1, random_state=42).reset_index(drop=True)

    # Separate features and labels again after balancing
    X = df_balanced.drop(columns=['Label'])
    y = df_balanced['Label']

    # Standardize (scale) the features to mean=0 and variance=1
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # Split the dataset into training and testing sets (80% train, 20% test)
    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, y, test_size=0.2, random_state=42)

    # Initialize and train the Random Forest classifier
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)

    # Make predictions and evaluate model performance
    y_pred = model.predict(X_test)
    print("Classification Report:\n", classification_report(y_test, y_pred))

    # Save the trained model and scaler to disk
    joblib.dump(model, "model.pkl")
    joblib.dump(scaler, "scaler.pkl")
    print("✅ Model and scaler saved!")

    # Output the distribution of final classes in the training set
    print("✅ Final training class distribution:")
    print(y.value_counts())
