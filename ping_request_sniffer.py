from scapy.all import *


class PingRequestSniffer:

    def __init__(self):
        pass
        #conf.route.add(host="192.168.87.180", gw="192.168.87.140")


    def sniff_ping_request(self, count):
        icmp_package = sniff(filter="icmp", count=count, promisc=True)

        return icmp_package