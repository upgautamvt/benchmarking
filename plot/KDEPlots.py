import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns

# Load the data from CSV files
vanilla_data = pd.read_csv('total_statistics_vanilla.csv')
bpf_data = pd.read_csv('total_statistics_bpf.csv')
absorb_data = pd.read_csv('total_statistics_absorb.csv')

# Verify column names (uncomment if you want to check)
# print(vanilla_data.columns)
# print(bpf_data.columns)
# print(absorb_data.columns)

# Extract the latency data (e.g., Avg us)
latencies_vanilla = vanilla_data['Avg(us)']
latencies_bpf = bpf_data['Avg(us)']
latencies_absorb = absorb_data['Avg(us)']

# Set up the matplotlib figure
plt.figure(figsize=(12, 6))

# Plot histograms with KDE
sns.histplot(latencies_vanilla, bins=30, color='blue', kde=True, label='Vanilla', stat='density', alpha=0.5)
sns.histplot(latencies_bpf, bins=30, color='orange', kde=True, label='BPF', stat='density', alpha=0.5)
sns.histplot(latencies_absorb, bins=30, color='green', kde=True, label='Absorb', stat='density', alpha=0.5)

# Add titles and labels
plt.title('Latency Distribution Comparison')
plt.xlabel('Average Latency (us)')
plt.ylabel('Density')
plt.legend()

# Show the plot
plt.grid()
plt.show()
