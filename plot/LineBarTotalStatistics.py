import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
import numpy as np
import pandas as pd

# File names for different environments
files = ['total_statistics_vanilla.csv', 'total_statistics_absorb.csv', 'total_statistics_bpf.csv']
labels = ['Vanilla', 'Absorb', 'BPF']
colors = ['red', 'black', 'green']
line_styles = ['-', '--', ':']  # Solid, dashed, dotted
markers = ['o', 's', '^']  # Circle, square, triangle

# Initialize the plot
plt.figure(figsize=(12, 6))

# Loop through each file to read data and plot
for i, (file, label, color) in enumerate(zip(files, labels, colors)):
    # Read the CSV file
    data = pd.read_csv(file)

    # Set the Time(s) as the x-axis
    x = data['Time(s)']

    # Plotting average latencies with error bars
    plt.errorbar(x, data['Avg(us)'], yerr=data['Std_dev'], fmt=f'{line_styles[i]}{markers[i]}', color=color,
                 ecolor='red', elinewidth=1, capsize=2, linewidth=1, alpha=0.7, label=f'Avg Latency ({label})')

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
