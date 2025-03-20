from scapy.contrib.pfcp import PFCP, PFCPSessionModificationRequest, PFCPSessionModificationResponse, PFCPSessionDeletionRequest, PFCPSessionDeletionResponse
from scapy.contrib.pfcp import IE_CreateFAR, IE_FAR_Id, IE_ApplyAction, IE_ForwardingParameters, IE_DestinationInterface, IE_NetworkInstance, IE_OuterHeaderCreation,  IE_BAR_Id
from scapy.layers.inet import IP, UDP
from scapy.all import send, sniff, AsyncSniffer
import logging
import threading
import os
import time
from datetime import datetime

PFCP_CP_IP_V4 = "10.0.14.40"
PFCP_UP_IP_V4 = "10.0.14.45"

class PfcpSkeleton(object):
    def __init__(self, pfcp_cp_ip, pfcp_up_ip):
        self.pfcp_cp_ip = pfcp_cp_ip
        self.pfcp_up_ip = pfcp_up_ip
        self.ts = int((datetime.now() - datetime(1900, 1, 1)).total_seconds())
        self.seq = 1
        self.seid_counter = 1  # Zmienna do przechowywania SEID
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        self.logger = logging.getLogger(__name__)

    def modification_request(self):
        self.cur_seid = self.seid_counter
        self.seid_counter += 1

        # Utwórz Create FAR IE
        create_far = IE_CreateFAR(
            IE_list=[
                IE_FAR_Id(id=10),  # FAR ID ustawione na 10
                IE_ApplyAction(FORW=1, DROP=1),
                IE_ForwardingParameters(),
                IE_DestinationInterface(),
                IE_NetworkInstance(instance="lo"),
                IE_OuterHeaderCreation(UDPIPV4=1, TEID=0x00000001, ipv4="10.0.13.50"),
                IE_BAR_Id(id=1)  # BAR ID ustawione na 1
            ]
        )

        # Konstrukcja i wysyłka PFCP Session Modification Request z Create FAR IE
        self.chat(PFCPSessionModificationRequest(IE_list=[create_far]), seid=self.cur_seid)

    def deletion_request(self):
        self.cur_seid = self.seid_counter
        self.seid_counter += 1
        self.chat(PFCPSessionDeletionRequest(), seid=self.cur_seid)  # Przekazanie SEID do pakietu

    def chat(self, pkt, seq=None, seid=None):
        self.logger.info(f"Wysyłanie pakietu z SEID: {seid}")
        send(
            IP(src=self.pfcp_cp_ip, dst=self.pfcp_up_ip) /
            UDP(sport=8805, dport=8805) /
            PFCP(
                version=1,
                S=1,  # Flaga SEID (S) ustawiona na 1, aby SEID było widoczne
                seid=seid,  # Ustaw SEID w pakiecie
                seq=self.seq if seq is None else seq) /
            pkt)
        if seq is None:
            self.seq += 1

    def signal_fun(self, signum, frame):
        self.deletion_request()
        os._exit(0)

    def listen_for_responses(self):
        def handle_packet(packet):
            if PFCP in packet:
                if PFCPSessionModificationResponse in packet:
                    self.logger.info(f"Otrzymano PFCP Session Modification Response: {packet.summary()}")
                elif PFCPSessionDeletionResponse in packet:
                    self.logger.info(f"Otrzymano PFCP Session Deletion Response: {packet.summary()}")

        sniffer = AsyncSniffer(filter=f"udp and port 8805 and host {self.pfcp_up_ip}", prn=handle_packet)
        sniffer.start()

class ModificationRequestThread(threading.Thread):
    def __init__(self, pfcp_client):
        threading.Thread.__init__(self)
        self.pfcp_client = pfcp_client

    def run(self):
        while True:
            self.pfcp_client.modification_request()
            time.sleep(3)  # Dodatkowe opóźnienie, aby uniknąć zbyt szybkiego wysyłania żądań

if __name__ == "__main__":
    pfcp_client = PfcpSkeleton(PFCP_CP_IP_V4, PFCP_UP_IP_V4)
    pfcp_client.listen_for_responses()  # Rozpocznij nasłuchiwanie odpowiedzi
    modification_thread = ModificationRequestThread(pfcp_client)
    modification_thread.start()
