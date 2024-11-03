import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
import numpy as np
import pandas as pd

# File names for different environments
files = ['get_statistics_vanilla.csv', 'get_statistics_absorb.csv', 'get_statistics_bpf.csv']
labels = ['Vanilla', 'Absorb', 'BPF']
colors = ['blue', 'orange', 'green']  # Colors for each environment

# Initialize the plot
plt.figure(figsize=(12, 6))

# Loop through each file to read data and plot
for file, label, color in zip(files, labels, colors):
    # Read the CSV file
    data = pd.read_csv(file)

    # Set the Time(s) as the x-axis
    x = data['Time(s)']

    # Plotting average latencies with error bars
    plt.errorbar(x, data['Avg(us)'], yerr=data['Std_dev'], fmt='-o', color=color,
                 ecolor='lightgray', elinewidth=2, capsize=5, label=f'Avg Latency ({label})')

    # Plotting min and max latencies as a fill_between
    plt.fill_between(x, data['Min(us)'], data['Max(us)'], color=color, alpha=0.1)

# Adding titles and labels
plt.title('Latency Over Time for Different Environments with Error Bars')
plt.xlabel('Time (s)')
plt.ylabel('Latency (microseconds)')

# Set y-axis to display full values instead of scientific notation
plt.gca().yaxis.set_major_formatter(mticker.StrMethodFormatter('{x:0.0f}'))

# Set x-axis ticks for finer granularity
plt.xticks(np.arange(0, x.max() + 20, 20), fontsize=8)

plt.legend()
plt.grid()

# Show the plot
plt.tight_layout()
plt.show()
