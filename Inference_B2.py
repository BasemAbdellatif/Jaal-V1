import numpy as np
#import serialize_B
#from scipy import spatial
from collections import Counter, defaultdict
import collections
#from sklearn.cluster import KMeans
import math
import csv



class inference:
    def __init__(self, summary_list):
        print("inference...")
        ### we should read the summaries as dictionaries
        self.summary1 = {}
        # self.summary2 = {}
        self.compined_summaries = {}
        self.compined_summaries_infe = {}
        self.summary_list = []

        for summary in summary_list:
            self.s = csv.DictReader(open(summary))
            for row in self.s:
                #print("row in S1 = {} ".format(row))
                my_dict = dict(row)
                self.summary1[my_dict['key']] = my_dict['val']
                self.compined_summaries[my_dict['key']] = my_dict['val']
                self.compined_summaries_infe[my_dict['key']] = summary
        # print("compined_summaries_infe = {}".format(self.compined_summaries_infe))
        
        # self.s1 = csv.DictReader(open(summary1))
        # for row in self.s1:
        #     #print("row in S1 = {} ".format(row))
        #     my_dict = dict(row)
        #     self.summary1[my_dict['key']] = my_dict['val']
        #     self.compined_summaries[my_dict['key']] = my_dict['val']
            
        # self.s2 = csv.DictReader(open(summary2))
        # for row in self.s2:
        #     #print("row in S2 = {} ".format(row))
        #     my_dict = dict(row)
        # #    print(row)
        #     self.summary1[my_dict['key']] = my_dict['val']
        #     self.compined_summaries[my_dict['key']] = my_dict['val']

		 


    def jaal_diff(self, q, v):
        # Implements the difference mechanism discussed in the paper
        diff_sum = 0
        count = 0
        for i in range(len(q)):
            if q[i] != -1:
                diff_sum += abs(q[i] - v[i])
                count+=1
        #print("count = {}".format(count))
        return diff_sum/count

    def transform_query(self, q_vector):
        temp = np.dot(np.transpose(q_vector), self.U)
        return np.dot(temp, np.linalg.inv(np.diag(self.S)))
            # print np.diag(self.S)
            # temp = np.dot(np.linalg.inv(np.diag(self.S)), np.transpose(self.U))
            # return np.dot(temp, q_vector)

    def reconstruct_matrix(self, U, S, V):
        U = np.append(U, np.zeros((len(U) , self.rank)), axis=1)
        S = np.append(S, np.zeros(self.rank))
        V = np.append(V, np.zeros((self.rank, V.shape[1])), axis = 0)
        packet_matrix = np.dot(U, np.dot(np.diag(S), V))
            # print np.transpose(packet_matrix)
        return packet_matrix

    def cosine_similarity(self, v1, v2):
        return np.dot(v1, v1) / (np.linalg.norm(v1) * np.linalg.norm(v2))


def my_main():
    print('my_main')
    # path_to_summary1 = "/home/babde006/s38_eth1_summary.csv"
    # path_to_summary2 = "/home/babde006/s39_eth1_summary.csv"

    infe = inference(path_to_summary1, path_to_summary2)
    #print(infe.compined_summaries)
    tt = 5
    Header_fields = 12
    SYN_index = 3
    query_vector = np.ones(Header_fields) * -1
    query_vector[SYN_index] = 1
    jaal_diff_list = []
    values = []
    attack_pkts = 0
    threshold = 10
    total_attack_pkts = .4 * 4000
    for key, val in infe.compined_summaries.items():
        key2 = str()
        key1 = []
        for elem in key:
            if elem == '[' or elem == ']':
                continue
            key2 += elem
        key3 = key2.split()
        for elem in key3:
            key1.append(float(elem))
        diff1 = infe.jaal_diff(query_vector,key1)
        jaal_diff_list.append(diff1)
        if int(val) >= threshold:
            attack_pkts += int(val)
            print("value = {}, jaal_diff = {}".format(int(val),diff1))
        values.append(int(val))
        
    #print("Jaal_diff_vector = {}".format(jaal_diff_list))
    #print("Ca = {}".format(values))
    if attack_pkts < total_attack_pkts:
        confidence  = attack_pkts / (1.0 * total_attack_pkts)
        false_alarm = 0
    else:
        confidence = 1
        false_alarm = (attack_pkts - total_attack_pkts) / (1.0 * total_attack_pkts)

    print("Sum = {} ".format(sum(values)))
    print("attack_pkts = {}".format(attack_pkts))
    print("confidence = {}, flase_alarm = {}".format(confidence, false_alarm))
# my_main()
if __name__ == '__ main__':

    my_main()











