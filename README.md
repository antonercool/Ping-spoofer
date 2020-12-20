# Ping-spoofer
The following project, involes a network sniffer that can captures ping reuqests on a local network and spoofs valid ping reply back to the requester. A rapport is included that documents the theory and implementation. An experiment is included where a firewall was enabled on Host B, to disable all incomming request, then a Host A should not be able to ping it. The ping and spoffer program, captures the request and spoofs and valid reply to Host A, even tho Host B discards the message. Proofs from wireshark shows that code works as expected.

## python prereqs ## 
- pip install scapy

### Any question ?  ###
You are welcome to write me an email at antonsihm@gmail.com


