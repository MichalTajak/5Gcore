import subprocess
import time
import random
import csv

# Lista skryptów do uruchomienia
scripts = ["pfcp_establishment.py", "pfcp_modification_dupl.py",  "pfcp_deletion.py"]
#scripts = ["pfcp_establishment.py", "pfcp_modification_dupl.py", "pfcp_modification_drop.py", "pfcp_deletion.py"]
total_duration = 10800
script_duration = 39
cnt = 0

# Czas rozpoczęcia
start_time = time.time()

# Nazwa pliku CSV
csv_file = "attack_logs.csv"

# Inicjalizacja pliku CSV i zapisanie nagłówków
with open(csv_file, mode='w', newline='') as file:
    writer = csv.writer(file)
    writer.writerow(["index", "Label","Label_val"])

while time.time() - start_time < total_duration:
    # Losowy wybór skryptu z listy
    if cnt % (len(scripts)+ 1) == 0:
        time.sleep(39)
        with open(csv_file, mode='a', newline='') as file:
                writer = csv.writer(file)
                writer.writerow([cnt, 'normal', 0])
    else:
        current_script = random.choice(scripts)
        try:
            # Drukujemy nazwę skryptu do debugowania
            print(f"Uruchamianie {current_script} przez {script_duration} sekund")
            
            # Zapisujemy nazwę skryptu do pliku CSV z aktualnym indeksem
            with open(csv_file, mode='a', newline='') as file:
                writer = csv.writer(file)
                if current_script == 'pfcp_establishment.py':
                    writer.writerow([cnt, "est_att", 3])
                elif current_script == "pfcp_modification_drop.py" or current_script == "pfcp_modification_dupl.py":
                    writer.writerow([cnt, "mod_att", 2])
                elif current_script == "pfcp_deletion.py":
                    writer.writerow([cnt, "del_att", 1])
                else:
                    writer.writerow([cnt, "mix_att", 4])
            # Debugowanie: potwierdzenie zapisu
            print(f"Zapisano do CSV: {cnt}, {current_script}")

            # Uruchamiamy skrypt za pomocą python3
            subprocess.run(["python3", current_script], timeout=script_duration)
        except subprocess.TimeoutExpired:
            print(f"Zakończono {current_script} po {script_duration} sekundach")
        except Exception as e:
            print(f"Błąd podczas uruchamiania {current_script}: {e}")
    
    cnt += 1
    time.sleep(1)
