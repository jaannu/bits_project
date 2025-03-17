import os
import csv
import numpy as np
import netStat as ns
from scapy.all import IP, TCP, UDP, IPv6, ARP, ICMP

class FE:
    def __init__(self, file_path=None, limit=np.inf):
        self.path = file_path
        self.limit = limit
        self.curPacketIndx = 0

        # Enable live mode if no file is given
        if file_path is None:
            print("🟢 Live Mode Enabled: Processing packets in real-time")
            self.parse_type = "live"
        else:
            self.__prep__()

        maxHost = 100000000000
        maxSess = 100000000000
        self.nstat = ns.netStat(np.nan, maxHost, maxSess)

    def __prep__(self):
        if self.path and not os.path.isfile(self.path):
            print(f"❌ File {self.path} does not exist!")
            raise Exception()

    def get_next_vector(self, live_packet=None):
        if self.parse_type == "live":
            if live_packet is None:
                return []

            try:
                IPtype = np.nan
                timestamp = live_packet.time
                framelen = len(live_packet)

                if live_packet.haslayer(IP):  
                    srcIP = live_packet[IP].src
                    dstIP = live_packet[IP].dst
                    IPtype = 0
                elif live_packet.haslayer(IPv6):  
                    srcIP = live_packet[IPv6].src
                    dstIP = live_packet[IPv6].dst
                    IPtype = 1
                else:
                    srcIP, dstIP = '', ''

                if live_packet.haslayer(TCP):
                    srcproto = str(live_packet[TCP].sport)
                    dstproto = str(live_packet[TCP].dport)
                elif live_packet.haslayer(UDP):
                    srcproto = str(live_packet[UDP].sport)
                    dstproto = str(live_packet[UDP].dport)
                else:
                    srcproto, dstproto = '', ''

                srcMAC = live_packet.src
                dstMAC = live_packet.dst

                return self.nstat.updateGetStats(IPtype, srcMAC, dstMAC, srcIP, srcproto, dstIP, dstproto,
                                                 int(framelen), float(timestamp))
            except Exception as e:
                print(f"⚠️ Error in Feature Extraction: {e}")
                return []

        return []
