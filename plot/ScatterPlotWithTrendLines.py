import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns

# Load the data from CSV files
vanilla_data = pd.read_csv('total_statistics_vanilla.csv')
bpf_data = pd.read_csv('total_statistics_bpf.csv')
absorb_data = pd.read_csv('total_statistics_absorb.csv')

# Extract the time and average latency data
time_vanilla = vanilla_data['Time(s)']
latencies_vanilla = vanilla_data['Avg(us)']

time_bpf = bpf_data['Time(s)']
latencies_bpf = bpf_data['Avg(us)']

time_absorb = absorb_data['Time(s)']
latencies_absorb = absorb_data['Avg(us)']

# Set up the matplotlib figure
plt.figure(figsize=(12, 6))

# Scatter plot with trend lines
sns.scatterplot(x=time_vanilla, y=latencies_vanilla, color='blue', label='Vanilla', marker='o')
sns.regplot(x=time_vanilla, y=latencies_vanilla, scatter=False, color='blue', line_kws={'linestyle': '--'})

sns.scatterplot(x=time_bpf, y=latencies_bpf, color='orange', label='BPF', marker='o')
sns.regplot(x=time_bpf, y=latencies_bpf, scatter=False, color='orange', line_kws={'linestyle': '--'})

sns.scatterplot(x=time_absorb, y=latencies_absorb, color='green', label='Absorb', marker='o')
sns.regplot(x=time_absorb, y=latencies_absorb, scatter=False, color='green', line_kws={'linestyle': '--'})

# Add titles and labels
plt.title('Average Latency Over Time with Trend Lines')
plt.xlabel('Time (s)')
plt.ylabel('Average Latency (us)')
plt.legend()
plt.grid()

# Show the plot
plt.show()
