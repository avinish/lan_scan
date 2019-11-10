import scapy.layers.l2
from scapy.sendrecv import sr
from scapy.layers.inet import IP,TCP,ICMP
import logging
from prettytable import PrettyTable
import threading,click

common_port = [21,22,23,25,53,67,68,69,80,123,161,162,389,443,3389]

logging.basicConfig(format='%(asctime)s %(levelname)-5s %(message)s', datefmt='%Y-%m-%d %H:%M:%S', level=logging.CRITICAL)
logger = logging.getLogger(__name__)

open_port_dict = {}
mac_oui = {}


def scan_port (ip,port) :
    logging.info ("scanning port %s for ip %s" % (port,ip)) 
    ans, unans = sr(IP(dst=ip) / TCP(dport=port),timeout=5,verbose=False)
    for s,r in ans :
        if not r.haslayer (ICMP) :
            if r.payload.flags == 0x12 :
                logging.info ("port %s is open for IP %s" % (port,ip))
                open_port_dict [ip].append(port)
    logging.debug (" open port list %s , remove port %s" %(open_port_dict[ip], port))

def scan_port_open(ip,port_list=common_port) :
    threads = []
    open_port_dict [ip] = [] 
    for port in port_list:
        t = threading.Thread(target=scan_port, args=(ip,port,))
        threads.append(t)
        t.start()
    for t in threads:
        t.join()

    logging.info (" list of port open %s for ip %s " % (open_port_dict[ip],ip))

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
    mac_oui [mac] = oui

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
x=PrettyTable()
x.field_names = ["MAC","IP","OPEN PORTS","OUI"]

threads = []
for mac,ip in ans_list:
    x.add_row([mac,ip,"---fetching info please wait","--fetching info please wait"])
    t = threading.Thread(target=scan_port_open, args=(ip,))
    t1 = threading.Thread(target=scan_oui, args=(mac,))
    threads.append(t)
    threads.append(t1)
    t.start()
    t1.start()

print (x)

for t in threads:
    t.join()
    t1.join()


logging.info (open_port_dict)
logging.info (mac_oui)

x.clear_rows()
for ans in ans_list :
    x.add_row ([ans[0],ans[1],open_port_dict[ans[1]],mac_oui[ans[0]]])

print ("\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/")
print (x)



