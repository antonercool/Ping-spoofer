from ping_request_sniffer import *
from ping_package_spoofer import * 
import time

smart_phone_local_ip = "192.168.87.187"
smart_phone_mac = "74-D0-2B-26-AE-A7"

unkown_device = "192.168.87.152"

if __name__ == "__main__":
    ping_sniffer = PingRequestSniffer()
    ping_package_spoofer = PingPackageSpoofer()

    while True:
        print("sniffing for icmp packet")
        packet =  ping_sniffer.sniff_ping_request()

        if len(packet)  != 0:  
            spoof_responce = ping_package_spoofer.spoof_reponse(packet[0])
            ping_package_spoofer.send_spoof_resonse(spoof_responce)
