from scapy.all import *


class PingRequestSniffer:

    def __init__(self):
        pass

    def sniff_ping_request(self):
        icmp_package = sniff(filter="icmp", count=1)

        if icmp_package[0].getlayer(ICMP).type == 8:
            print("ECHO request sniifed !!!")
            return icmp_package
        else:
            return []    
