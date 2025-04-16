import subprocess
import os
import pandas as pd
import numpy as np
import tables as tb
import argparse

# Mapowanie typów wiadomości PFCP na czytelne nazwy
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

        # Wyodrębnij nazwę pliku bez rozszerzenia i dodaj rozszerzenie .csv z interwałem
        file_name = os.path.basename(pcap_file)
        file_base_name = os.path.splitext(file_name)[0]
        self.final_csv_file = os.path.join(output_directory, f'{file_base_name}_{interval}.csv')
        self.final_h5_file = os.path.join(output_directory, f'{file_base_name}_{interval}.h5')

    def convert_pcap_to_csv(self):
        command_csv = [
            'tshark',
            '-r', self.pcap_file,  # Plik wejściowy .pcap
            '-Y', 'pfcp',  # Filtr przechwytywania dla PFCP
            '-T', 'fields',
            '-E', 'separator=,',
            '-E', 'quote=d',
            '-e', 'frame.time_relative',  # Czas
            '-e', 'ip.src',  # Adres źródłowy
            '-e', 'ip.dst',  # Adres docelowy
            '-e', 'pfcp.msg_type',  # Typ wiadomości PFCP (jako liczba)
            '-e', 'frame.len',  # Długość ramki
            '-E', 'header=y'  # Nagłówek CSV
        ]

        print(f"Converting {self.pcap_file} to {self.temp_csv_file}")
        with open(self.temp_csv_file, 'w') as file:
            subprocess.run(command_csv, stdout=file)  # Zapis do pliku CSV
        print(f"Conversion completed: {self.temp_csv_file}")

    def add_message_type_names(self):
        with open(self.temp_csv_file, 'r') as file:
            lines = file.readlines()

        with open(self.final_csv_file, 'w') as file:
            # Dodaj nagłówki kolumn
            file.write('frame.time,ip.src,ip.dst,pfcp.msg_type,frame.len,info\n')
            for line in lines[1:]:  # Pomijaj nagłówek
                parts = line.strip().split(',')
                text = parts[3].replace('"', '')
                try:
                    msg_type_name = pfcp_msg_type_map.get(int(text), 'unknown')  
                    # Dodaj nową kolumnę 'info' z nazwą typu wiadomości
                    file.write(f'{",".join(parts)},{msg_type_name}\n')
                except:
                    pass

    def process_csv(self):
        df = pd.read_csv(self.final_csv_file)

        # Sprawdź dane, aby upewnić się, że są poprawne
        #print(df.head())

        min_time = df['frame.time'].min()
        max_time = df['frame.time'].max()

        # Utwórz etykiety przedziałów czasowych
        bins = np.arange(min_time, max_time + self.interval, self.interval)
        labels = [f"part_{i + 1}" for i in range(len(bins) - 1)]

        # Przydziel każdemu wierszowi odpowiedni przedział czasowy
        df['part'] = pd.cut(df['frame.time'], bins=bins, labels=labels, include_lowest=True)

        # Grupowanie i liczenie wartości 'info'
        df_grouped = df.groupby(['part', 'info']).size().reset_index(name='count')

        # Tworzenie tabeli przestawnej z wszystkimi wartościami ze słownika jako kolumny
        df_final = df_grouped.pivot_table(index='part', columns='info', values='count', fill_value=0)
        for msg_type_name in pfcp_msg_type_map.values():
            if msg_type_name not in df_final.columns:
                df_final[msg_type_name] = 0

        # Resetowanie indeksu i usuwanie kolumny 'part'
        df_final.reset_index(inplace=True)
        df_final.drop(columns=['part'], inplace=True)
        if 'Label' in df_final.columns:
            # Zapis do pliku CSV
            df_final.to_csv(self.final_csv_file, index=False)
        else:
            df_final = self.manual_create_label(df_final)
            df_final.to_csv(self.final_csv_file, index=False)
        
        '''
        # Zapis wdo pliku HDF5
        with tb.open_file(self.final_h5_file, mode='w') as h5file:
            h5file.create_table('/', 'pfcp_data', obj=df_final.to_records(index=False))

        '''

    def manual_create_label(self, df):
        names = ['heartbeat', 'session_deletion', 'session_modification', 'session_establishment']
        # Dodanie nowych kolumn Label_val i Label do DataFrame
        df['Label_val'] = 4  # Domyślna wartość to 4
        df['Label'] = 'mix_att'  # Domyślna wartość to 'mix_att'
    
        for index, row in df.iterrows():
            row_to_sum = row.drop(labels=['Label_val','Label'])
            total_sum = row_to_sum.sum()  # Suma wszystkich kolumn
            # Sprawdzanie sum wybranych kolumn
            for i, name in enumerate(names):
                selected_sum = row[f'{name}_request'] + row[f'{name}_request']  # Suma wybranych kolumn
                # Sprawdzenie, czy selected_sum stanowi co najmniej 70% total_sum
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
        # Upewnienie się, że folder wyjściowy istnieje
        if not os.path.exists(self.output_directory):
            os.makedirs(self.output_directory)

        # Konwersja PCAP na CSV
        self.convert_pcap_to_csv()

        # Dodanie nazw typów wiadomości
        self.add_message_type_names()

        # Przetwarzanie i podział danych na przedziały czasowe
        self.process_csv()

        # Usunięcie tymczasowego pliku CSV
        os.remove(self.temp_csv_file)
        print(f"Temporary file {self.temp_csv_file} removed")


def process_all_pcaps_in_directory(data_directory, output_directory, interval):
    # Upewnienie się, że folder wyjściowy istnieje
    if not os.path.exists(output_directory):
        os.makedirs(output_directory)

    # Iteracja przez wszystkie pliki w podanym folderze
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
