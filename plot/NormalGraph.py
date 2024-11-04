import numpy as np
import matplotlib.pyplot as plt
import pandas as pd

# Load the CSV files
files = ['total_statistics_vanilla.csv', 'total_statistics_bpf.csv', 'total_statistics_absorb.csv']
labels = ['Vanilla', 'BPF', 'Absorb']
colors = ['#0033cc', '#006600', '#cc0033']

# Create a figure for the plot
plt.figure(figsize=(12, 8))

for index, (file, label, color) in enumerate(zip(files, labels, colors)):
    # Read the data
    df = pd.read_csv(file)

    # Extract the 'Avg(us)' column
    avg_latency = df['Avg(us)']

    # Calculate mean and standard deviation
    mean = avg_latency.mean()
    std_dev = avg_latency.std()

    # Generate data for the normal distribution
    x = np.linspace(mean - 4 * std_dev, mean + 4 * std_dev, 1000)
    y = (1 / (std_dev * np.sqrt(2 * np.pi))) * np.exp(-0.5 * ((x - mean) / std_dev) ** 2)

    # Plotting the normal distribution
    plt.plot(x, y, label=f'{label}', color=color)
    plt.axvline(mean, color=color, linestyle='solid', linewidth=1)

    # Adjust the vertical position of the mean label
    plt.text(mean, 0.005 + (index * 0.002), f'μ: {mean:.2f}', color=color, ha='center', va='bottom')

    # Draw lines for ±1 standard deviation and label
    plt.axvline(mean + std_dev, color=color, linestyle='dashed', linewidth=1)
    plt.axvline(mean - std_dev, color=color, linestyle='dashed', linewidth=1)
    plt.text(mean + std_dev, 0.0015 + (index * 0.002), f'μ + σ: {mean + std_dev:.2f}', color=color, ha='left', va='bottom', fontsize=9)
    plt.text(mean - std_dev, 0.0015 + (index * 0.002), f'μ - σ: {mean - std_dev:.2f}', color=color, ha='right', va='bottom', fontsize=9)

    # Draw lines for ±2 standard deviations and label
    plt.axvline(mean + 2 * std_dev, color=color, linestyle='dashed', linewidth=1)
    plt.axvline(mean - 2 * std_dev, color=color, linestyle='dashed', linewidth=1)
    plt.text(mean + 2 * std_dev, 0.0015 + (index * 0.002), f'μ + 2σ: {mean + 2 * std_dev:.2f}', color=color, ha='left', va='bottom', fontsize=9)
    plt.text(mean - 2 * std_dev, 0.0015 + (index * 0.002), f'μ - 2σ: {mean - 2 * std_dev:.2f}', color=color, ha='right', va='bottom', fontsize=9)

# Customize the plot
plt.title('Normal Distributions of Avg Latency with Means and Standard Deviations')
plt.xlabel('Avg Latency (us)')
plt.ylabel('Probability Density')
plt.legend()
plt.grid()

# Show the plot
plt.tight_layout()
plt.show()
