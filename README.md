# Simple-Network-Scanner

This is a simple network scanner, created using Python 3 and Scapy (https://github.com/secdev/scapy/), as part of a personal learning exercise. 

HOWTO:  
*-h*&nbsp;&nbsp;&nbsp;&nbsp;prints help message
*-p <integer>*&nbsp;&nbsp;&nbsp;&nbsp;the number of processes to run in parallel (default: 10)  
*-dns <IPv4 address>*&nbsp;&nbsp;&nbsp;&nbsp;the DNS server to be used for our querries (default = "8.8.8.8")

After starting the program, it prompts for the IPv4 subnet (e.g. e.g. 192.168.1.0/24) or just an IPv4 address to be scanned.  
  
Explanations how code works can be found in my following blog posts: 
- Making a Ping Scanner Using Scapy: https://atlasbros.blogspot.com/2020/05/making-ping-scanner-using-scapy-by.html
- Ping Scanner Part 2: Multi-Processing: https://atlasbros.blogspot.com/2020/05/ping-scanner-continued-multi-processing.html
- Ping Scanner Part 3: Using a DNS Server to resolve Responsive IP Addresses: https://atlasbros.blogspot.com/2020/08/ping-scanner-part-3-using-dns-server-to.html
- Turning the Ping Scanner into a Network Scanner: https://atlasbros.blogspot.com/2020/09/turning-ping-scanner-into-network.html
- Filtering and collecting the results: https://atlasbros.blogspot.com/2020/12/filtering-and-collecting-results-from.html

For comments / suggestions, please email me at: vaggelis DOT atlasis AT gmail DOT com

Enjoy :-) 

Vaggelis
