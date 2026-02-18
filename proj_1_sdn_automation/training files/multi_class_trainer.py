import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
import seaborn as sns
import matplotlib.pyplot as plt
import joblib
import os

# --- Configuration ---
# The specialist datasets created by your individual collectors and combiners
DATASET_FILES = {
    'tcp': 'tcp_final_training_data.csv',
    'udp': 'udp_final_training_data.csv',
    'icmp': 'icmp_final_training_data.csv'
}
# The name for the final, unified multi-class model
MODEL_FILENAME = 'multi_class_model.joblib'

# --- The master list of all features used across all models ---
# The final DataFrame must have all these columns.
# We will fill missing ones with 0.
ALL_FEATURES = [
    'total_packet_rate', 'total_byte_rate', 'avg_packet_size',
    'tcp_rate', 'udp_rate', 'icmp_rate',
    'syn_rate', 'ack_rate', 'syn_to_ack_ratio',
    'tcp_to_total_ratio', 'udp_to_total_ratio', 'icmp_to_total_ratio',
    'unique_source_ips'
]

def main():
    """
    Loads data from three specialist CSVs, combines them into a multi-class
    dataset, trains a single RandomForestClassifier, and saves it.
    """
    print("--- Starting Multi-Class Model Trainer ---")

    all_dataframes = []
    
    # --- Step 1: Load and re-label each specialist dataset ---
    print("\nLoading and processing individual datasets...")
    
    # TCP Data (Label 0 for Normal, 1 for TCP Flood)
    if os.path.exists(DATASET_FILES['tcp']):
        df_tcp = pd.read_csv(DATASET_FILES['tcp'])
        # The 'label' column is already 0 (Normal) or 1 (TCP Flood), which is perfect.
        all_dataframes.append(df_tcp)
        print(f"✅ Loaded {len(df_tcp)} rows from '{DATASET_FILES['tcp']}'")
    else:
        print(f"⚠️ Warning: TCP data file '{DATASET_FILES['tcp']}' not found. Skipping.")

    # UDP Data (Label 0 for Normal, re-label Attack to 2)
    if os.path.exists(DATASET_FILES['udp']):
        df_udp = pd.read_csv(DATASET_FILES['udp'])
        # Re-label: 1 (generic attack) becomes 2 (UDP Flood)
        df_udp['label'] = df_udp['label'].replace({1: 2})
        all_dataframes.append(df_udp)
        print(f"✅ Loaded {len(df_udp)} rows from '{DATASET_FILES['udp']}' (Attack label -> 2)")
    else:
        print(f"⚠️ Warning: UDP data file '{DATASET_FILES['udp']}' not found. Skipping.")
        
    # ICMP Data (Label 0 for Normal, re-label Attack to 3)
    if os.path.exists(DATASET_FILES['icmp']):
        df_icmp = pd.read_csv(DATASET_FILES['icmp'])
        # Re-label: 1 (generic attack) becomes 3 (ICMP Flood)
        df_icmp['label'] = df_icmp['label'].replace({1: 3})
        all_dataframes.append(df_icmp)
        print(f"✅ Loaded {len(df_icmp)} rows from '{DATASET_FILES['icmp']}' (Attack label -> 3)")
    else:
        print(f"⚠️ Warning: ICMP data file '{DATASET_FILES['icmp']}' not found. Skipping.")

    if not all_dataframes:
        print("❌ Error: No data files were loaded. Aborting.")
        return

    # --- Step 2: Combine all data into a single master DataFrame ---
    master_df = pd.concat(all_dataframes, ignore_index=True)

    # --- Step 3: Standardize the feature set ---
    # Ensure all columns from ALL_FEATURES are present, filling missing ones with 0.
    # This is crucial because, for example, the UDP dataset won't have 'syn_rate'.
    for col in ALL_FEATURES:
        if col not in master_df.columns:
            master_df[col] = 0
    # Reorder columns to ensure consistency
    master_df = master_df[ALL_FEATURES + ['label']]
    
    # Remove duplicate "Normal" rows that came from each file
    # Keep the first instance of each normal row and all attack rows
    normal_rows = master_df[master_df['label'] == 0]
    attack_rows = master_df[master_df['label'] != 0]
    unique_normal_rows = normal_rows.drop_duplicates()
    
    master_df = pd.concat([unique_normal_rows, attack_rows], ignore_index=True)
    
    print(f"\n✅ Combined and cleaned datasets. Final total rows: {len(master_df)}")

    # --- Step 4: Shuffle the master dataset ---
    master_df = master_df.sample(frac=1).reset_index(drop=True)
    print("🔀 Shuffled the master dataset randomly.")

    # --- Step 5: Train the multi-class model ---
    X = master_df.drop('label', axis=1)
    y = master_df['label']
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.25, random_state=42, stratify=y)

    print("\nTraining the unified multi-class model...")
    multi_class_classifier = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    multi_class_classifier.fit(X_train, y_train)
    print("✅ Model training complete.")

    # --- Step 6: Export the final model ---
    joblib.dump(multi_class_classifier, MODEL_FILENAME)
    print(f"💾 Unified model saved successfully to '{MODEL_FILENAME}'")

    # --- Step 7: Evaluate the model ---
    print("\n--- Multi-Class Model Evaluation ---")
    y_pred = multi_class_classifier.predict(X_test)
    target_names = ['Normal', 'TCP SYN Flood', 'UDP Flood', 'ICMP Flood']
    
    # Check if all expected labels are present in y_test
    present_labels = sorted(y_test.unique())
    report_target_names = [target_names[i] for i in present_labels]

    print(classification_report(y_test, y_pred, target_names=report_target_names, zero_division=0))

    print("\nConfusion Matrix:")
    cm = confusion_matrix(y_test, y_pred, labels=present_labels)
    sns.heatmap(cm, annot=True, fmt='d', cmap='YlGnBu', 
                xticklabels=report_target_names, yticklabels=report_target_names)
    plt.ylabel('Actual Label')
    plt.xlabel('Predicted Label')
    plt.title('Multi-Class Model Confusion Matrix')
    plt.show()

if __name__ == "__main__":
    main()