import scapy.layers.l2
from scapy.sendrecv import sr
from scapy.layers.inet import IP,TCP,ICMP
import logging
from prettytable import PrettyTable

common_port = [21,22,23,25,53,67,68,69,80,123,161,162,389,443,3389]

logging.basicConfig(format='%(asctime)s %(levelname)-5s %(message)s', datefmt='%Y-%m-%d %H:%M:%S', level=logging.DEBUG)
logger = logging.getLogger(__name__)

def scan_port_open(ip,port_list=common_port) :
    open_port_list = []
    for port in port_list :
        logging.info ("scanning port %s for ip %s " % (ip,port))
        ans, unans = sr(IP(dst=ip) / TCP(dport=port),timeout=5,verbose=False)
        for s,r in ans :
            if not r.haslayer (ICMP) :
                if r.payload.flags == 0x12 :
                    logging.info ("port %s is open for IP %s" % (port,ip))
                    open_port_list.append(port)
    logging.info (" list of port open %s for ip %s " % (open_port_list,ip))
    return open_port_list

def scan_oui(mac) :
    mac_list=mac.split(":")
    oui = ""
    mac_first_three_oct=str(mac_list[0]+mac_list[1]+mac_list[2])
    logging.info ("searching mac %s" % mac_first_three_oct)
    f = open('oui.txt','r', encoding='utf-8')
    for line in f:
        result = re.match(r'([A-F0-9]+)\s+\(base 16\)\s+([a-zA-Z0-9\-\_ \(\)\,\.]+)', line,re.M|re.I)
        if result :
            if result.group(1) == mac_first_three_oct.upper() :
                logging.info ("Found OUI %s" % result.group(2))
                oui = result.group(2)
                break
    f.close()
    return oui

########## main ###################

##### Enter you network and interface here #######
network_scan="192.168.1.0/24"
interface_scan="wlan0"
############################################

ans, unans=scapy.layers.l2.arping (network_scan,iface=interface_scan,timeout=5,verbose=False)
ans_list = []

for s,r in ans.res :
    ans_list.append ([r.sprintf("%Ether.src%"),r.sprintf("%ARP.psrc%")])

logging.info (ans_list)

index=0
for mac,ip in ans_list :
    ans_list[index].append(scan_port_open (ip))
    ans_list[index].append(scan_oui (mac))
    index = index + 1
    logging.info (ans_list)

x = PrettyTable()

x.field_names = ["MAC","IP","OPEN PORTS","OUI"]

for ans in ans_list :
    x.add_row (ans)

print (x)


