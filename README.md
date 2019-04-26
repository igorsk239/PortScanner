# PortScanner

Port scanner is using two techniques for scanning. First one is TCP-SYN scan and second one uses UDP packets.
	UDP technique is able to detect:  open or closed status.
	TCP  SYN is able to detect:  open, filtered or closed status.
  
# Usage pattern  

	./ipk-scan {-i <interface>} -pu <port-ranges> -pt <port-ranges> [<domain-name> | <IP-address>]\

	-i    user selected interface name
	-pu   specifies udp ports for scan
	-pt   specifies tcp ports for scan

	<interface>     interface name
	<port-ranges>   range of ports for scan
	<domain-name>   domain name beging scanned
	<IP-address>    IPv4 or IPv6 adress being scanned

# Usage examples:

	./ipk-scan –pt 22,80,1000,1001,1002,1003 nemeckay.net
	./ipk-scan –pu 20,23 –pt 22,80,1000,1001,1002,1003 localhost
	./ipk-scan –i tun0 –pu22-80merlin6.fit.vutbr.cz
	./ipk-scan–i eth0–pu 10-13–pt 20-30 localhost
