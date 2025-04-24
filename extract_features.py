import pandas as pd

# Load dataset
df = pd.read_csv("./Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv")
df.columns = df.columns.str.strip()
# Print column names to inspect and clean them
# print(df.columns)

important_features = ['Destination Port', 'Flow Duration',
                      'Total Fwd Packets', 'Flow Packets/s', 'Label']

df_selected = df[important_features]
df_selected.to_csv("top_features_portscan.csv", index=False)
print("✅ Top features saved to top_features_portscan.csv")
