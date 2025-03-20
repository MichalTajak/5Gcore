from scapy.all import sniff, wrpcap, get_if_list
import time
from threading import Thread

# Definiowanie adresów IP do filtrowania
IP1 = "10.0.14.45" #N4 UPF
#IP1 = "10.0.13.45" #N3 UPF
#IP1 = "10.0.19.45" #N9 UPF
capture_duration = 3600  # Czas przechwytywania w sekundach
iface = "br-8a599ea23a63"  #N4 int
#iface = "br-a06450588026" #N3 int
#iface = "br-639f93cf89a0" #N9 int

# Sprawdzenie dostępnych interfejsów
print("Dostępne interfejsy:", get_if_list())

# Funkcja do zapisywania pakietów do pliku
def save_packets(packets, filename):
    wrpcap(filename, packets)

# Funkcja do przechwytywania pakietów
def capture_packets():
    print("Rozpoczynanie przechwytywania na interfejsie:", iface)
    packets = sniff(iface=iface, filter=f"host {IP1}", timeout=capture_duration)
    print(f"Przechwycono {len(packets)} pakietów")
    return packets

def periodic_capture():
    while True:
        filename = f"captured_packets_{int(time.time())}.pcap"
        packets = capture_packets()
        if packets:
            save_packets(packets, filename)
            print(f"Saved {len(packets)} packets to {filename}")
        else:
            print("Brak przechwyconych pakietów")
        time.sleep(1)

if __name__ == "__main__":
    # Uruchamianie przechwytywania pakietów w osobnym wątku
    capture_thread = Thread(target=periodic_capture)
    capture_thread.start()
