import pandas as pd

def extractVanillaData():
    # Read data from the file
    with open('benchmark_vanilla.txt', 'r') as file:
        data = file.read()

    # Split the data into sections
    sections = data.strip().split("\n\n")

    # Initialize lists to store the results
    get_data = []
    set_data = []
    total_data = []

    # Process each section
    for section in sections:
        lines = section.strip().split("\n")
        title = lines[0].strip()  # Get the title

        # Collect only the Period rows
        for line in lines[2:]:
            if "Period" in line:
                values = line.split()
                if title.startswith("Get"):
                    get_data.append(values)  # Add to Get data
                elif title.startswith("Set"):
                    set_data.append(values)  # Add to Set data
                elif title.startswith("Total"):
                    total_data.append(values)  # Add to Total data

    # Extract only the specified lines for Get, Set, and Total
    get_data_filtered = get_data  # All lines for Get
    set_data_filtered = set_data  # All lines for Set
    total_data_filtered = total_data  # All lines for Total

    # Function to create DataFrame and save to CSV
    def save_to_csv(title, data):
        df = pd.DataFrame(data,
                          columns=["Type", "Time(s)", "Ops", "TPS(ops/s)", "Net(M/s)", "Get_miss", "Min(us)", "Max(us)",
                                   "Avg(us)", "Std_dev", "Geo_dist"])
        df['Time(s)'] = (df.index + 1) * 10  # Cumulative time for each period
        df = df.drop(columns=['Type'])
        df.to_csv(f"{title}_statistics_vanilla.csv", index=False)

    # Save the filtered data to CSV files
    save_to_csv("get", get_data_filtered)
    save_to_csv("set", set_data_filtered)
    save_to_csv("total", total_data_filtered)

    print("CSV files generated successfully.")


def extractBpfData():
    # Read data from the file
    with open('benchmark_bpf.txt', 'r') as file:
        data = file.read()

    # Split the data into sections
    sections = data.strip().split("\n\n")

    # Initialize lists to store the results
    get_data = []
    set_data = []
    total_data = []

    # Process each section
    for section in sections:
        lines = section.strip().split("\n")
        title = lines[0].strip()  # Get the title

        # Collect only the Period rows
        for line in lines[2:]:
            if "Period" in line:
                values = line.split()
                if title.startswith("Get"):
                    get_data.append(values)  # Add to Get data
                elif title.startswith("Set"):
                    set_data.append(values)  # Add to Set data
                elif title.startswith("Total"):
                    total_data.append(values)  # Add to Total data

    # Extract only the specified lines for Get, Set, and Total
    get_data_filtered = get_data  # All lines for Get
    set_data_filtered = set_data  # All lines for Set
    total_data_filtered = total_data  # All lines for Total

    # Function to create DataFrame and save to CSV
    def save_to_csv(title, data):
        df = pd.DataFrame(data,
                          columns=["Type", "Time(s)", "Ops", "TPS(ops/s)", "Net(M/s)", "Get_miss", "Min(us)", "Max(us)",
                                   "Avg(us)", "Std_dev", "Geo_dist"])
        df['Time(s)'] = (df.index + 1) * 10  # Cumulative time for each period
        df = df.drop(columns=['Type'])
        df.to_csv(f"{title}_statistics_bpf.csv", index=False)

    # Save the filtered data to CSV files
    save_to_csv("get", get_data_filtered)
    save_to_csv("set", set_data_filtered)
    save_to_csv("total", total_data_filtered)

    print("CSV files generated successfully.")


def extractAbsorbData():
    # Read data from the file
    with open('benchmark_absorb.txt', 'r') as file:
        data = file.read()

    # Split the data into sections
    sections = data.strip().split("\n\n")

    # Initialize lists to store the results
    get_data = []
    set_data = []
    total_data = []

    # Process each section
    for section in sections:
        lines = section.strip().split("\n")
        title = lines[0].strip()  # Get the title

        # Collect only the Period rows
        for line in lines[2:]:
            if "Period" in line:
                values = line.split()
                if title.startswith("Get"):
                    get_data.append(values)  # Add to Get data
                elif title.startswith("Set"):
                    set_data.append(values)  # Add to Set data
                elif title.startswith("Total"):
                    total_data.append(values)  # Add to Total data

    # Extract only the specified lines for Get, Set, and Total
    get_data_filtered = get_data  # All lines for Get
    set_data_filtered = set_data  # All lines for Set
    total_data_filtered = total_data  # All lines for Total

    # Function to create DataFrame and save to CSV
    def save_to_csv(title, data):
        df = pd.DataFrame(data,
                          columns=["Type", "Time(s)", "Ops", "TPS(ops/s)", "Net(M/s)", "Get_miss", "Min(us)", "Max(us)",
                                   "Avg(us)", "Std_dev", "Geo_dist"])
        df['Time(s)'] = (df.index + 1) * 10  # Cumulative time for each period
        df = df.drop(columns=['Type'])
        df.to_csv(f"{title}_statistics_absorb.csv", index=False)

    # Save the filtered data to CSV files
    save_to_csv("get", get_data_filtered)
    save_to_csv("set", set_data_filtered)
    save_to_csv("total", total_data_filtered)

    print("CSV files generated successfully.")


if __name__ == "__main__":
    extractVanillaData()
    extractBpfData()
    extractAbsorbData()
