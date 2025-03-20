from datetime import datetime
from scapy.contrib.pfcp import PFCP, PFCPSessionEstablishmentRequest, PFCPSessionEstablishmentResponse
from scapy.layers.inet import IP, UDP
from scapy.all import send, sniff, AsyncSniffer
import logging
import threading
import os
import time

PFCP_CP_IP_V4 = "10.0.14.40"
PFCP_UP_IP_V4 = "10.0.14.45"

class PfcpSkeleton(object):
    def __init__(self, pfcp_cp_ip, pfcp_up_ip):
        self.pfcp_cp_ip = pfcp_cp_ip
        self.pfcp_up_ip = pfcp_up_ip
        self.ts = int((datetime.now() - datetime(1900, 1, 1)).total_seconds())
        self.seq = 1
        self.seid_counter = 1  # Variable to store SEID
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        self.logger = logging.getLogger(__name__)

    def establishment_request(self):
        self.cur_seid = self.seid_counter
        self.seid_counter += 1
        self.chat(PFCPSessionEstablishmentRequest(), seid=self.cur_seid)  # Pass SEID to the packet

    def deletion_request(self):
        self.cur_seid = self.seid_counter
        self.seid_counter += 1
        self.chat(PFCPSessionDeletionRequest(), seid=self.cur_seid)  # Pass SEID to the packet

    def chat(self, pkt, seq=None, seid=None):
        self.logger.info(f"Sending packet with SEID: {seid}")
        send(
            IP(src=self.pfcp_cp_ip, dst=self.pfcp_up_ip) /
            UDP(sport=8805, dport=8805) /
            PFCP(
                version=1,
                S=1,  # SEID flag (S) set to 1 to make SEID visible
                seid=seid,  # Set SEID in the packet
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
                if PFCPSessionEstablishmentResponse in packet:
                    self.logger.info(f"Received PFCP Session Establishment Response: {packet.summary()}")
                elif PFCPSessionDeletionResponse in packet:
                    self.logger.info(f"Received PFCP Session Deletion Response: {packet.summary()}")

        sniffer = AsyncSniffer(filter=f"udp and port 8805 and host {self.pfcp_up_ip}", prn=handle_packet)
        sniffer.start()

class EstablishmentRequestThread(threading.Thread):
    def __init__(self, pfcp_client):
        threading.Thread.__init__(self)
        self.pfcp_client = pfcp_client

    def run(self):
        while True:
            self.pfcp_client.establishment_request()
            time.sleep(1)  # Additional delay to avoid sending requests too quickly

if __name__ == "__main__":
    pfcp_client = PfcpSkeleton(PFCP_CP_IP_V4, PFCP_UP_IP_V4)
    pfcp_client.listen_for_responses()  # Start listening for responses
    establishment_thread = EstablishmentRequestThread(pfcp_client)
    establishment_thread.start()
