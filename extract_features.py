# Import the pandas library for data manipulation and analysis
import pandas as pd

# Load the dataset from a CSV file into a DataFrame
# The file contains captured network traffic labeled with potential security threats
df = pd.read_csv("./Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv")

# Strip any leading or trailing whitespace characters from the column names
# This ensures consistency when referencing column names later in the script
df.columns = df.columns.str.strip()

# Define a list of important features to extract from the dataset
# These features are relevant for identifying or analyzing port scan attacks
important_features = ['Destination Port',    # The port on the destination host to which traffic is sent
                      'Flow Duration',       # The duration of the network flow
                      'Total Fwd Packets',   # Total number of packets in the forward direction
                      'Flow Packets/s',      # Packet rate in the flow
                      'Label']               # Label indicating whether the flow is benign or an attack

# Create a new DataFrame that includes only the selected important features
df_selected = df[important_features]

# Save the new DataFrame to a CSV file
# This can be used later for training or evaluating machine learning models
df_selected.to_csv("top_features_portscan.csv", index=False)

# Print a confirmation message once the file is successfully saved
print("✅ Top features saved to top_features_portscan.csv")
