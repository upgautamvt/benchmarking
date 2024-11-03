import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
import numpy as np
import pandas as pd

# File names for different environments
files = ['get_statistics_vanilla.csv', 'get_statistics_absorb.csv', 'get_statistics_bpf.csv']
labels = ['Vanilla', 'Absorb', 'BPF']
colors = ['blue', 'orange', 'green']  # Colors for each environment

# Initialize lists to store means and standard deviations
tps_means = []
net_means = []
tps_stds = []
net_stds = []

# Process each file
for file in files:
    data = pd.read_csv(file)
    # Calculate mean and standard deviation for TPS and Net
    tps_means.append(data['TPS(ops/s)'].mean())
    net_means.append(data['Net(M/s)'].mean())
    tps_stds.append(data['TPS(ops/s)'].std())
    net_stds.append(data['Net(M/s)'].std())

# Set up the bar graph
x = np.arange(len(labels))  # the label locations
width = 1  # width of the bars

# Create subplots
fig, ax = plt.subplots(1, 2, figsize=(12, 6))

# Bar graph for TPS
for i in range(len(labels)):
    ax[0].bar(x[i] - width, tps_means[i], width, yerr=tps_stds[i], capsize=5, color=colors[i], alpha=0.7,
              label=labels[i])

ax[0].set_title('Throughput (TPS) with Standard Deviation')
ax[0].set_ylabel('TPS (ops/s)')
ax[0].set_xticks(x)
ax[0].set_xticklabels(labels, fontsize=10)
ax[0].yaxis.set_major_formatter(mticker.StrMethodFormatter('{x:0.0f}'))  # Format y-axis
ax[0].grid()

# Add values on top of the TPS bars
for i in range(len(labels)):
    yval = tps_means[i]
    ax[0].text(x[i] - width, yval, f'{yval:.1f}', ha='center', va='bottom', fontsize=10)

# Bar graph for Net rate
for i in range(len(labels)):
    ax[1].bar(x[i] - width, net_means[i], width, yerr=net_stds[i], capsize=5, color=colors[i], alpha=0.5,
              label=labels[i])

ax[1].set_title('Net Rate with Standard Deviation')
ax[1].set_ylabel('Net Rate (M/s)')
ax[1].set_xticks(x)
ax[1].set_xticklabels(labels, fontsize=10)
ax[1].yaxis.set_major_formatter(mticker.StrMethodFormatter('{x:0.0f}'))  # Format y-axis
ax[1].grid()

# Add values on top of the Net Rate bars
for i in range(len(labels)):
    yval = net_means[i]
    ax[1].text(x[i] - width, yval, f'{yval:.1f}', ha='center', va='bottom', fontsize=10)

# Adjust layout
plt.tight_layout()

# Add legends for each environment to both subplots, positioned outside
ax[0].legend(labels, loc='upper left', bbox_to_anchor=(-0.2, 1), fontsize=8)
ax[1].legend(labels, loc='upper left', bbox_to_anchor=(-0.2, 1), fontsize=8)

# Show the plot
plt.show()
