import subprocess
import os
import pandas as pd
import numpy as np
import tables as tb
import argparse

# Mapping PFCP message types to readable names
pfcp_msg_type_map = {
    1: "heartbeat_request",
    2: "heartbeat_response",
    3: "pfd_management_request",
    4: "pfd_management_response",
    5: "association_setup_request",
    6: "association_setup_response",
    7: "association_update_request",
    8: "association_update_response",
    9: "association_release_request",
    10: "association_release_response",
    11: "version_not_supported_response",
    12: "node_report_request",
    13: "node_report_response",
    14: "session_set_deletion_request",
    15: "session_set_deletion_response",
    50: "session_establishment_request",
    51: "session_establishment_response",
    52: "session_modification_request",
    53: "session_modification_response",
    54: "session_deletion_request",
    55: "session_deletion_response",
    56: "session_report_request",
    57: "session_report_response",
}


class PcapCsvConverter:
    def __init__(self, data_directory, pcap_file, output_directory, interval=120):
        self.data_directory = data_directory
        self.pcap_file = os.path.join(data_directory, pcap_file)
        self.output_directory = output_directory
        self.interval = interval
        self.temp_csv_file = os.path.join(output_directory, 'temp_pcap.csv')

        # Extract the file name without extension and add .csv with interval
        file_name = os.path.basename(pcap_file)
        file_base_name = os.path.splitext(file_name)[0]
        self.final_csv_file = os.path.join(output_directory, f'{file_base_name}_{interval}.csv')
        self.final_h5_file = os.path.join(output_directory, f'{file_base_name}_{interval}.h5')

    def convert_pcap_to_csv(self):
        command_csv = [
            'tshark',
            '-r', self.pcap_file,
            '-Y', 'pfcp',  
            '-T', 'fields',
            '-E', 'separator=,',
            '-E', 'quote=d',
            '-e', 'frame.time_relative',  
            '-e', 'ip.src',  
            '-e', 'ip.dst',  
            '-e', 'pfcp.msg_type',  # PFCP message type (as number)
            '-e', 'frame.len',  # Frame length
            '-E', 'header=y'  # CSV header
        ]

        print(f"Converting {self.pcap_file} to {self.temp_csv_file}")
        with open(self.temp_csv_file, 'w') as file:
            subprocess.run(command_csv, stdout=file)  # Save to CSV file
        print(f"Conversion completed: {self.temp_csv_file}")

    def add_message_type_names(self):
        with open(self.temp_csv_file, 'r') as file:
            lines = file.readlines()

        with open(self.final_csv_file, 'w') as file:
           # Add column headers
            file.write('frame.time,ip.src,ip.dst,pfcp.msg_type,frame.len,info\n')
            for line in lines[1:]:  # Skip header
                parts = line.strip().split(',')
                text = parts[3].replace('"', '')
                try:
                    msg_type_name = pfcp_msg_type_map.get(int(text), 'unknown')  
                    # Add new column 'info' with message type name
                    file.write(f'{",".join(parts)},{msg_type_name}\n')
                except:
                    pass

    def process_csv(self):
        df = pd.read_csv(self.final_csv_file)

        min_time = df['frame.time'].min()
        max_time = df['frame.time'].max()

        # Create time interval labels
        bins = np.arange(min_time, max_time + self.interval, self.interval)
        labels = [f"part_{i + 1}" for i in range(len(bins) - 1)]

        df['part'] = pd.cut(df['frame.time'], bins=bins, labels=labels, include_lowest=True)

        # Group and count 'info' values
        df_grouped = df.groupby(['part', 'info']).size().reset_index(name='count')

        # Create pivot table with all values from the dictionary as columns
        df_final = df_grouped.pivot_table(index='part', columns='info', values='count', fill_value=0)
        for msg_type_name in pfcp_msg_type_map.values():
            if msg_type_name not in df_final.columns:
                df_final[msg_type_name] = 0

        # Reset index and remove 'part' column
        df_final.reset_index(inplace=True)
        df_final.drop(columns=['part'], inplace=True)
        if 'Label' in df_final.columns:
            df_final.to_csv(self.final_csv_file, index=False)
        else:
            df_final = self.manual_create_label(df_final)
            df_final.to_csv(self.final_csv_file, index=False)
        
        '''
        # Save to HDF5 file
        with tb.open_file(self.final_h5_file, mode='w') as h5file:
            h5file.create_table('/', 'pfcp_data', obj=df_final.to_records(index=False))
        '''

    def manual_create_label(self, df):
        names = ['heartbeat', 'session_deletion', 'session_modification', 'session_establishment']
        # Add new columns Label_val and Label to DataFrame
        df['Label_val'] = 4  # Default value is 4
        df['Label'] = 'mix_att'  # Default label is 'mix_att'
    
        for index, row in df.iterrows():
            row_to_sum = row.drop(labels=['Label_val','Label'])
            total_sum = row_to_sum.sum()  # Sum of all columns
            # Check selected columns
            for i, name in enumerate(names):
                selected_sum = row[f'{name}_request'] + row[f'{name}_request']  # Sum of selected columns
                # Check if selected_sum is at least 70% of total_sum
                if i == 0:
                    if selected_sum >= 0.8 * total_sum:
                        df.at[index, 'Label_val'] = i
                        df.at[index, 'Label'] = 'normal'
                        break
                else:
                    if selected_sum >= 0.2 * total_sum:
                        df.at[index, 'Label_val'] = i
                        if i == 1:
                            df.at[index, 'Label'] = 'del_att'
                        elif i == 2:
                            df.at[index, 'Label'] = 'mod_att'
                        elif i == 3:
                            df.at[index, 'Label'] = 'est_att'
                        break
        
        return df

    def run(self):
        if not os.path.exists(self.output_directory):
            os.makedirs(self.output_directory)

        # Convert PCAP to CSV
        self.convert_pcap_to_csv()

        # Add readable message type names
        self.add_message_type_names()

        # Process and split data into time intervals
        self.process_csv()

        # Remove temporary CSV file
        os.remove(self.temp_csv_file)
        print(f"Temporary file {self.temp_csv_file} removed")


def process_all_pcaps_in_directory(data_directory, output_directory, interval):
    if not os.path.exists(output_directory):
        os.makedirs(output_directory)

    # Iterate through all files in the given folder
    processed_files_count = 0
    for filename in os.listdir(data_directory):
        if filename.endswith('.pcap'):
            print(f"Processing file: {filename}")
            processor = PcapCsvConverter(data_directory, filename, output_directory, interval)
            processor.run()
            processed_files_count += 1

    print(f"Total .pcap files processed: {processed_files_count}")


def main():
    parser = argparse.ArgumentParser(description='Process PCAP files and convert them to CSV and HDF5 formats.')
    parser.add_argument('data_directory', type=str, help='Directory containing the .pcap files')
    parser.add_argument('output_directory', type=str, help='Directory to save the processed files')
    parser.add_argument('--interval', type=int, default=120,
                        help='Time interval for splitting data (default: 120 seconds)')

    args = parser.parse_args()

    process_all_pcaps_in_directory(args.data_directory, args.output_directory, args.interval)


if __name__ == '__main__':
    main()
