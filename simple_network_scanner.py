from scapy.all import IP, ICMP, TCP, sr1, UDP, DNS, RandShort, DNSQR
from ipaddress import IPv4Network, ip_address
from multiprocessing import Pool
from argparse import ArgumentParser

dns_server=None

tcp_common_ports = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "domain name system",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    443: "https",
    445: "microsoft-ds",
    993: "imaps",
    995: "pop3s",
    1723: "pptp",
    3306: "mysql",
    3389: "ms-wbt-server",
    5900: "vnc",
    8080: "http-proxy" } 

#the following function will to resolve an IPv4 address to its host name
def resolve_IP(ip_address_to_resolve):
    global dns_server 
    reverse_ip_address = ip_address(ip_address_to_resolve).reverse_pointer
    #print("The reverse pointer of" , ip_address_to_resolve , "is" , reverse_ip_address)
    packet = IP(dst = dns_server)/UDP(dport = 53, sport = RandShort())/DNS(rd = 1, qd = DNSQR(qname = reverse_ip_address, qtype = "PTR"))
    response = sr1(packet, verbose = 0, timeout = 2)
    host_name = "not resolved"
    if response:
        if int(response.getlayer(UDP).sport) == 53:
            try:
                #print("The host name of" , ip_address_to_resolve , "is" , response.an.rdata.decode('utf-8'))
                host_name = response.an.rdata.decode('utf-8')
            except Exception as e:
                pass
    return host_name

        
def send_ping(address):
    packet = IP(dst = str(address))/ICMP(type = 8, code = 0)
    response = sr1(packet, verbose = 0, timeout = 2)
    if response:
        if int(response.getlayer(ICMP).type) == 0:
            host_name = resolve_IP(address)
            print("Host" , address , "is reachable. Its host name is" , host_name)
            send_tcp(address)
        elif int(response.getlayer(ICMP).type) == 3:
            print("Destination" , address , "is unreachable")

def send_tcp(address):
    ports = list(tcp_common_ports.keys()) ##returns a list of all keys (aka port numbers) of tcp_common_ports dictionary
    for p in ports:
        packet = IP(dst = str(address))/TCP(sport = RandShort(),dport = p, flags = "S")
        response = sr1(packet, verbose = 0, timeout = 2)
        if response:
            if response.haslayer(TCP):
                if str(response.getlayer(TCP).flags) == "SA":
                    print("Host ", address , "is listening in port",p,tcp_common_ports[p])
                elif str(response.getlayer(TCP.flags)) == "R":
                    print("Host ", address , "is rejecting conenction on port",p,tcp_common_ports[p])
            else:
                if int(response.getlayer(ICMP).type) == 3 and int(response.getlayer(ICMP).code) == 13:
                    print("Host " , address, ": communication prohibited on port",p,tcp_common_ports[p])
                else:
                    print(response.summary())
        

def main():
    parser = ArgumentParser()
    parser.add_argument("-p", "--processes" , help = "the number of processes to run in parallel (must be integer)"  , type = int, default = 10)
    parser.add_argument("-dns", "--dns_server" , help = "the DNS server to be used for our querries"  , type = str, default = "8.8.8.8")
    values = parser.parse_args()
   
    global dns_server 
    dns_server = values.dns_server

    network = input("Please enter the IPv4 network you'd like to scan (e.g. 192.168.1.0/24) or just an IPv4 address: ")
    valid_target = False
    while valid_target == False:
        try:
            targets = IPv4Network(network)
            valid_target = True
        except Exception as e:
            print(e)
            network = input("Please enter a valid IPv4 subnet: ")
            
    with Pool(values.processes) as process:
        process.map(send_ping, targets)


if __name__ == "__main__":
    main()
