from scapy.all import *


class PingPackageSpoofer:
    def __init__(self):
        pass

    def spoof_reponse(self, package):
        ehter_layer = package.getlayer(Ether)
        ip_layer = package.getlayer(IP)
        icmp_layer = package.getlayer(ICMP)

        #Copy seq, id from original request and generate new icmp request
       
        self.spoof_ether(package, ehter_layer)
        self.spoof_ip(package, ip_layer)
        self.spoof_icmp(package, icmp_layer)
       
        # clean up checksums
        del package[IP].chksum
        del package[ICMP].chksum
        # restore new checksums 
        raw_bytes = package.build()

        print("printing final spoofed ping response: \n")
        
        package[IP].chksum = Ether(raw_bytes)[IP].chksum
        package[ICMP].chksum = Ether(raw_bytes)[ICMP].chksum
        
        package.show()
        return package

    def send_spoof_resonse(self, package):
        sendp(package, iface="Ethernet 3")

    def spoof_ether(self, package, ehter_original):
        #fetch src, and dst
        dst = ehter_original.dst
        src = ehter_original.src
        # redirect
        package.dst = src
        package.src = dst 


    def spoof_ip(self, package,  ip_original):
        #fetch src, and dst
        dst = ip_original.dst
        src = ip_original.src
        # redirect
        package[IP].dst = src
        package[IP].src = dst 
        

    def spoof_icmp(self, package, icmp_original):
        #https://erg.abdn.ac.uk/users/gorry/course/inet-pages/icmp-code.html
        package[ICMP].type = 0
        package[ICMP].code = 0
