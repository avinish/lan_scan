# lan_scan
scanning your home network

These tool is developed with an idea to scan your home device in your home network.
There are multiple device in your network like NAS, Printer, Xbox, Smart TV, Android, Linux server etc.

These all device have an DHCP IP and sometime it is difficult to find out IP of device.

These tool help in finding out IP of tool.

It searches network device in your network using ARP PING and then matches their mac address with OUI tables.

Inorder to run the script in your linux / windows machine,
You need to install these below package in your python environment.

1. Scapy
2. PrettyTables
3. logging

You install these package via pip install <package name>

Also these script is written in python3.

So please use python3 module to run this script.

User should have root privilege to run this script.
Scapy tool require root previlige to run.
