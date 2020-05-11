#!/usr/bin/env python


## this will be the full Jaal code

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
from scipy.linalg import svd
from scipy import spatial
from collections import Counter, defaultdict
import collections
from sklearn.cluster import KMeans
import math

import central_controller_B
import deserialize_B_2
import serialize_B
import Inference_B2


def my_main():

    path_to_pcap = "combined_10000_10.pcap"       ## file contains the simulation packets
    path_to_config = 'config.txt'                 ## file contains the monitors interfaces that should monitor the traffic
    buffer_size = 10000              ## total number of simulated packets (attack + normal)
    Header_fields = 18              ## length of header fields 
    SYN_index = 3                   ## index of SYN field
    query_vector = np.ones(Header_fields) * -1          ## Initialization of question vector in jaal
    query_vector[SYN_index] = 1                 ## question vector in jaal
    jaal_diff_list = []         
    values = []
    att_val_diff_list = []
    threshold = 15          ## Snort Threshold 
    tau_d1 = .95            ## tau_d1 in Jaal
    tau_d2 = .99            ## tau_d2 in Jaal
    # total_attack_pkts = .1 * buffer_size
    centeriods = 160        ## number of k-means centriods

    ## thresold = 13, centroids = 150, true positive >= 90%, sent size = 25%
    rank = 14       ## required rank in Jaal 
    avg_confidence = 0      
    false_positive_rate = 0
    
    # summary_list = [] 		## list that contains names of summary files 




	## central controller part , read configuration file and assignes flows to monitors
    c = central_controller_B.centralController(path_to_pcap, buffer_size, path_to_config)
    print("monitors loads = {}".format(c.monitors_workload))
    dict_1 = c.flows_assignment
    ## writing the flows assignments in a .csv file, this file is shared and used by each monitor to check whether the current flow is assigned to him or not.
    w = csv.writer(open("flows_assignment.csv", "w"))  
    w.writerow(["key","val"])
    for key, val in dict_1.items():
        w.writerow([key, val])
    print("End of Controller\n")


    ## variables used to calculate the saved average overhead .
    number_of_interfaces = len(c.interfaces)
    Avg_summary_sizes = np.zeros((number_of_interfaces,1))
    full_summary_sizes = np.zeros((number_of_interfaces,1))
    percent = np.zeros((number_of_interfaces,1))



    ## we repeat the experiment 5 times and at each time we read 2000 pkts,
    ## and from these 2000 pkts we assume that the maximum number of attack pkts is 200
    Iterations = 5
    buffer_size_1 = 2000
    total_attack_pkts = .1 * buffer_size_1

    for itr in range(Iterations):
        print("Iteration {} ...".format(itr))
        startt = itr * buffer_size_1  ## start position in the pcap file 
        endd = startt + buffer_size_1 - 1  ## end position in the pcap file
        print("start = {}, end = {}".format(startt, endd))
        
        summary_list = []       ## list that contains names of summary files 
        serialize_dic = {}      ## a dictionary the will hold the serialize instance for every interface
        deserialize_dic = {}    ## a dictionary the will hold the deserialize instance for every interface

        ## varaibles to calculate the confidence and false alarm by the inference
        confidence = 0      
        false_alarm = 0
        attack_pkts = 0

        ii = 0
        for interface in c.interfaces:

            print("interface => {}".format(interface))
            ## each monitor calls serialize_B to do the following functions:
            ##      * create the original packets matrix 
            ##      * perform SVD and K_means

            s = serialize_B.Serialize_B(path_to_pcap, buffer_size_1, rank, startt, endd,'flows_assignment.csv',interface)
            # print("End of serialize_B.")
            model, U, S, V = s.k_means(centeriods)
            summary_size = 0
            ips_len = 0
            sum_tcp_len = sum(s.tcp_len_vec)
            full_summary_sizes[ii] = full_summary_sizes[ii] + sum_tcp_len / (1.0 * Iterations)

            ## each monitor calls deserialize_B_2 to do the following functions:
            ##      * reconstruct a matrix from the trauncated one
            d = deserialize_B_2.Deserialize(model, U, S, V, rank)
            ## getting the labels of the clusters and the number of elements in each cluster
            ## then we use this information and append it in the summary
            labels = model.labels_
            counter = Counter(labels)
            cluster_centers = model.cluster_centers_
            
            my_dict = {}
            for label, count in counter.most_common(centeriods):
                my_dict[label] = count
            summary_file = interface + '_summary.csv'
            ## we create a dictionary of the summaries and thier serialze/deserialize objects
            ## in case we needed them in the feedback loop
            serialize_dic[summary_file] = s
            deserialize_dic[summary_file] = d

            if summary_file not in summary_list:
                summary_list.append(summary_file) 
            ## we get the size of the summary by calculating the sizes of the clusters' centers
            f1 = csv.writer(open(summary_file,'w')) 
            f1.writerow(['key','val'])
            for center in cluster_centers:
                prediction = model.predict(center.reshape(1,rank))

                if prediction[0] in my_dict:
                    count1 = my_dict[model.predict(center.reshape(1,rank))[0]]
                    f1.writerow([str(center), str(count1)])

                    for ll in range(s.cnt):

                        if ( model.predict(U[ll].reshape(1,rank))==prediction[0] ):

                            summary_size += s.tcp_len_vec[ll]
                            ips_len += s.ip_len_vec[ll]
                            break

                else: 
                    continue
            Avg_summary_sizes[ii] = Avg_summary_sizes[ii] + summary_size /(1.0 * Iterations)
            ii += 1


        print("Avg_summary_sizes = {}".format(Avg_summary_sizes))
        print("full_summary_sizes = {}".format(full_summary_sizes))
        for iii in range(number_of_interfaces):
            percent[iii] = Avg_summary_sizes[iii] /(1.0* full_summary_sizes[iii])
            print("Avg_summary_sizes[{}] / full_summary_sizes[{}] = {}".format(iii, iii, percent[iii]))
            print("Avg_percent = {}".format(sum(percent)/(1.0 * number_of_interfaces)))
        print("Avg_percent = {}".format(sum(Avg_summary_sizes)/(1.0 * sum(full_summary_sizes))))


        rannge = 0
        ## the inference class reads and combines the summaries
        ## then check the elements in the combined summary against the question vector 
        infe = Inference_B2.inference(summary_list)

        for key, val in infe.compined_summaries.items():
            key2 = str()
            key1 = []
            for elem in key:
                if elem == '[' or elem == ']' or elem == '\\' or elem == 'n':
                    continue
                key2 += elem
            key3 = key2.split()
            for elem in key3:
                key1.append(float(elem))
            ## getting the distance between the summary element and the question vector
            diff1 = infe.jaal_diff(query_vector,key1)
            jaal_diff_list.append(diff1)

            if diff1 <= tau_d1 : 
                attack_pkts += int(val)
                att_val_diff_list.append((int(val),diff1))
            
            if diff1 > tau_d1 and diff1 <= tau_d2:

                ## performaing feedback 
                index_list = []
                summary_name = infe.compined_summaries_infe[key]
                d1 = deserialize_dic[summary_name]

                prediction_label = d1.model.predict(np.asarray(key1).reshape(1,rank))
                for row1 in range(d1.U.shape[0]):
                    # print(d1.U[row1])
                    if d1.model.predict(d1.U[row1].reshape(1,rank)) == prediction_label:
                        index_list.append(row1)
                U2 = np.zeros((len(index_list),d1.U.shape[1]))
                for row2 in range(len(index_list)):
                    U2[row2] = d1.U[index_list[row2]]
                matrix_to_be_sent = d1.reconstruct_matrix(U2, d1.S, d1.V)

                ## this is for just SYN flood , only for now
                if len(index_list) >= threshold:
                    attack_pkts += int(val)


                rannge += 1

            values.append(int(val))
        
        ## this part is not the correct way for calculating the True Positive Rate and False Positive Rate for actual scenarios,
        ##  we assume that it is correct here because we tailored the attack scenario and we know the number of attack packets at each iteration before hand  
        if attack_pkts < total_attack_pkts:
            confidence  = attack_pkts / (1.0 * total_attack_pkts)
            false_alarm = 0
        else:
            confidence = 1
            false_alarm = (attack_pkts - total_attack_pkts) / (1.0 * total_attack_pkts)

        print("Sum = {} ".format(sum(values)))
        print("attack_pkts = {}".format(attack_pkts))
        print("confidence = {}, flase_alarm = {}".format(confidence, false_alarm))

        avg_confidence += confidence / (1.0 * Iterations)
        false_positive_rate += false_alarm / (1.0 * Iterations)
        # print("att_val_diff_list = {}".format(att_val_diff_list))
        print("rannge = {}".format(rannge))

    print("True_positive_rate = {}, False_positive_rate = {}".format(avg_confidence, false_positive_rate))







if __name__ == '__main__':
    my_main()
    