from ping_request_sniffer import *
import time

smart_phone_local_ip = "192.168.87.187"
smart_phone_mac = "74-D0-2B-26-AE-A7"

unkown_device = "192.168.87.152"

if __name__ == "__main__":
    ping_sniffer = PingRequestSniffer()

    while True:
        print("sniffing for icmp packets")
        packets =  ping_sniffer.sniff_ping_request(count = 2)
        
        for pack in packets:
            pack.show()
            #pack.getlayer(IP).show()
            #pack.getlayer(ICMP).show()  