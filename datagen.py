import pandas as pd
import numpy as np
import random
import os
from datetime import datetime

def generate_sample_log(num_rows):
    """
    Generate sample log data with specified number of rows
    """
    # Define the columns
    columns = [
        'Flow_ID', 'Flow_Duration', 'Tot_Fwd_Pkts', 'Tot_Bwd_Pkts', 
        'Fwd_Pkt_Len_Mean', 'Bwd_Pkt_Len_Mean', 'Flow_Byts/s', 'Flow_Pkts/s', 
        'Flow_IAT_Mean', 'Fwd_Header_Len', 'Bwd_Header_Len', 'Flow_Flags', 'Protocol'
    ]
    
    # Generate data
    data = []
    
    # Define ranges for each feature
    for i in range(num_rows):
        flow_id = f"id{i+1}"
        
        # Generate values with some randomness
        flow_duration = random.uniform(0.01, 2.0)
        tot_fwd_pkts = random.randint(0, 5000)
        tot_bwd_pkts = random.randint(0, 100)
        fwd_pkt_len_mean = random.uniform(0, 1000)
        bwd_pkt_len_mean = random.uniform(0, 1000)
        flow_byts_s = random.uniform(0, 1000000)
        flow_pkts_s = random.uniform(0, 20000)
        flow_iat_mean = random.uniform(0, 0.1)
        fwd_header_len = random.randint(20, 60)
        bwd_header_len = random.randint(20, 60)
        flow_flags = random.randint(0, 10)
        protocol = random.choice([6, 17, 1])  # TCP, UDP, ICMP
        
        row = [
            flow_id, flow_duration, tot_fwd_pkts, tot_bwd_pkts,
            fwd_pkt_len_mean, bwd_pkt_len_mean, flow_byts_s, flow_pkts_s,
            flow_iat_mean, fwd_header_len, bwd_header_len, flow_flags, protocol
        ]
        
        data.append(row)
    
    # Create DataFrame
    df = pd.DataFrame(data, columns=columns)
    
    return df

def main():
    print("=== Sample Log Generator ===")
    
    # Get user input for number of rows
    while True:
        try:
            num_rows = int(input("Enter the number of rows to generate (1-1000): "))
            if 1 <= num_rows <= 1000:
                break
            else:
                print("Please enter a number between 1 and 1000.")
        except ValueError:
            print("Please enter a valid number.")
    
    # Generate the log data
    print(f"\nGenerating {num_rows} rows of sample log data...")
    log_data = generate_sample_log(num_rows)
    
    # Create output directory if it doesn't exist
    output_dir = "generated_logs"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # Generate filename with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"sample_log_{timestamp}_{num_rows}_rows.csv"
    filepath = os.path.join(output_dir, filename)
    
    # Save to CSV
    log_data.to_csv(filepath, index=False)
    
    print(f"\nSample log generated successfully!")
    print(f"File saved to: {filepath}")
    print(f"Number of rows: {num_rows}")
    print(f"File size: {os.path.getsize(filepath)} bytes")
    
    # Display first few rows
    print("\nFirst 5 rows of the generated data:")
    print(log_data.head())
    
    # Display column information
    print("\nColumn information:")
    for col in log_data.columns:
        print(f"- {col}: {log_data[col].dtype}")

if __name__ == "__main__":
    main()