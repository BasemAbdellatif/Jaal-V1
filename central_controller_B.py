#!/usr/bin/env python


from scapy.all import *
import numpy as np
from time import time
from collections import OrderedDict
import logging
from math import sqrt
import csv
import multiprocessing as mp
import numpy as np
import dpkt
import socket
import struct




######################################################################
# Total number of packet dimensions
NUM_HEADER_FIELDS = 22

# Index values for IP header fields
SIP_INDEX = 0 # Source IP
DIP_INDEX = 1 # Destination IP
DF_INDEX= 2 # Do not fragment flag
MF_INDEX = 3 # More fragments flag
TTL_INDEX = 4 # Time to live
PROTO_INDEX = 5 # Protocol: 1 = ICMP; 2 = IGMP; 6 = TCP; 17 = UDP

# Index values for common TCP/UDP header fields
SPORT_INDEX = 6 # Source port
DPORT_INDEX = 7 # Destination port

# Index values for common TCP/UDP/ICMP header fields
CHECKSUM_INDEX = 8

# Index values for common TCP header fields
SEQ_INDEX = 9
ACK_INDEX = 10
WIN_INDEX = 11
FIN_INDEX = 12
SYN_INDEX = 13
RST_INDEX = 14
PUSH_INDEX = 15
TCP_ACK_INDEX = 16
URG_INDEX = 17
ECE_INDEX = 18
CWR_INDEX = 19

# Index values for common ICMP header fields
TYPE_INDEX = 20
CODE_INDEX = 21

# Max values for normalization
MAX_SPORT = 65531
MAX_DPORT = 65416
MAX_SEQ = 4293617831
MAX_ACK = 4293617831
MAX_WIN = 65535
MAX_SUM = 65528
MAX_S_IP = 3757027264
MAX_D_IP = 3744647062
MAX_TTL = 255
MAX_PROTO = 255
MAX_TYPE = 255
MAX_CODE = 255

## IPv4 flags
DF_FLAG = 2 ## Do not fragment
MF_FLAG = 1 ## More fragments



class centralController:
    def __init__(self, traffic_file_path, buffer_size, interfaces_file):
        print("centralController...")

        self.total_pkts = buffer_size
        self.flows_assignment = {}   ## a dictionary to hold the flows assignments as { flow tuple : interface  }
        self.interfaces_file = interfaces_file ## File containing config info
        self.interfaces = [] ## List of ethernet interfaces of the monitors
        self.fnames = [] ## List of files containing background traffic
        self.iface_fnames = [] ## Contains background traffic file of each interface

        self.read_file(interfaces_file) ## function to read the configuration file
        
        
        self.monitors_workload = [() for i in range(len(self.interfaces))]   ## workload for each interface that will be used for flow assignment 

        
        ## Read and extract config ino
        cnt = 0
        for i in self.interfaces:
            self.monitors_workload[cnt] = (i,0)
            cnt += 1



        self.read_packets(traffic_file_path, self.flows_assignment, self.total_pkts)

        
    def read_file(self, interfaces_file):
        try:    
            with open(interfaces_file, "r") as ins:
                for line in ins:
                    l = line.split() ## interface filename
                    
                    if l[0] not in self.interfaces:
                        self.interfaces += [l[0]]
                        self.iface_fnames += [l[1]]
                        
                    if l[1] not in self.fnames:
                        self.fnames += [l[1]]
                    
        except IOError as e:
            print("[ConfigExtractor] I/O error({0}): {1}".format(e.errno, e.strerror))



    def create_flow_str(self, ip):  
        str1 = ''
        str1 = str(ip[0]) + str(ip[1]) + str(ip[2]) + str(ip[3])
        return str1


    def read_packets(self, input_packet_source, flows_dictionary, buffer_size):

        flow_info = np.zeros(4)

        with open(input_packet_source, 'rb') as f:
            pcap = dpkt.pcap.Reader(f)

            count = 0
            for time, packet in pcap:
                eth = dpkt.ethernet.Ethernet(packet)

                if isinstance(eth.data, dpkt.ip.IP) and isinstance(eth.data.data, dpkt.tcp.TCP):

                    if count == buffer_size:
                        return

                    ip = eth.data
                    tcp = ip.data
                    source = ip.src
                    destination = ip.dst

                    flow_info[0] = self.normalize(self.inet_to_str(source), MAX_S_IP)
                    flow_info[1] = self.normalize(self.inet_to_str(destination), MAX_D_IP)
                    flow_info[2] = self.normalize(tcp.sport, MAX_SPORT)
                    flow_info[3] = self.normalize(tcp.dport, MAX_DPORT)
                    flow_info[0] = self.inet_to_str(source)
                    flow_info[1] = self.inet_to_str(destination)
                    flow_info[2] = tcp.sport
                    flow_info[3] = tcp.dport
                    flow_str = self.create_flow_str(flow_info)  ## function to create the flow tuple

                    if flow_str in self.flows_assignment:
                        continue
                    else:
                        index, infc, load = self.get_min_workload_monitor(self.monitors_workload)
                        self.flows_assignment[flow_str] = infc
                        self.monitors_workload[index] = (infc, load + 1)
                        
                    count+=1





    def get_min_workload_monitor(self, monitors):
        m = 0
        min_load = 1000000000000
        index = 0
        for monitor in monitors:
            m1 = int(monitor[1])
            if min_load > monitor[1]:
                m = m1
                min_load = monitor[1]
                index = monitors.index((monitor[0], monitor[1]))
                infc = monitor[0]
                load = monitor[1]
        return index, infc, load



    def inet_to_str(self, inet):
        """Convert inet object to a string
            Args:
                inet (inet struct): inet network address
            Returns:
                str: Printable/readable IP address
        """
        try:
            ip_string = socket.inet_ntop(socket.AF_INET, inet)
            ip_struct = socket.inet_aton(ip_string)
            return struct.unpack("!L", ip_struct)[0]
        except ValueError:
            ip_string = socket.inet_ntop(socket.AF_INET, inet)
            ip_struct = socket.inet_aton(ip_string)
            return struct.unpack("!L", ip_struct)[0]

    def normalize(self, value, data_max):
        if value >= data_max:
            return 1.0
        else:
            return (value - 0.000) / (data_max - 0.0000)





def my_main():
    path_to_pcap_normal = "/home/babde006/compined_40.pcap"
    path_to_config = '/home/babde006/config.txt'
    buffer_size = 4000
    c = centralController(path_to_pcap_normal, buffer_size, path_to_config)
    # print("flows_assignment = {}".format(c.flows_assignment))
    print("monitors loads = {}".format(c.monitors_workload))
    # print("flows_assignment = {}".format(c.flows_assignment))





    # dict = {'Python' : '.py', 'C++' : '.cpp', 'Java' : '.java'}
    dict_1 = c.flows_assignment
    w = csv.writer(open("flows_assignment.csv", "w"))
    w.writerow(["key","val"])
    for key, val in dict_1.items():
        w.writerow([key, val])




if __name__ == '__main__':
    my_main()
    print("End of Controller")
