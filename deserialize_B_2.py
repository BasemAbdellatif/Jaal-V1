import numpy as np
import serialize_B
from scipy import spatial
from collections import Counter, defaultdict
import collections
from sklearn.cluster import KMeans
import math
import csv
# import sklearn

class Deserialize:

    def __init__(self,model, U, S, V, rank):
        print("Deserialize_B_2...")
        self.model = model
        self.U = U
        self.S = S
        self.V = V
        self.rank = rank
        self.dict = []
        self.packet_matrix = self.reconstruct_matrix(U, S, V)  # reconstructed matrix of integer values

    def transform_query(self, q_vector):
        temp = np.dot(np.transpose(q_vector), self.U)
        return np.dot(temp, np.linalg.inv(np.diag(self.S)))


    def reconstruct_matrix(self, U, S, V):
        U = np.append(U, np.zeros((len(U) , self.rank)), axis=1)
        S = np.append(S, np.zeros(self.rank))
        V = np.append(V, np.zeros((self.rank, V.shape[1])), axis = 0)
        packet_matrix = np.dot(U, np.dot(np.diag(S), V))
        return packet_matrix

    def cosine_similarity(self, v1, v2):
        return np.dot(v1, v1) / (np.linalg.norm(v1) * np.linalg.norm(v2))

    def jaal_diff(self, q, v):
        # Implements the difference mechanism discussed in the paper
        diff_sum = 0
        count = 0
        for i in range(len(q)):
            if q[i] != -1:
                diff_sum += abs(q[i] - v[i])
                count+=1
        return diff_sum/count


def main():
    buffer_size = 2000
    # centeriods = int(math.ceil(10/100.0 * buffer_size))
    centeriods = 200
    # print("centeriods = {}".format(centeriods))
    np.set_printoptions(suppress=True)
    path_to_pcap = "/home/babde006/traffic1.pcap"
    rank = 12
    print(path_to_pcap)
    avg_confidence = 0
    false_positive_rate = 0
    iterations = 1

    for i in range (iterations):
        # print("iteration = {}".format(i))
        startt = i * buffer_size
        endd = startt + buffer_size -1
        startt = 0
        endd = buffer_size
        # print("endd = {}".format(endd))
        s = serialize_B.Serialize_B(path_to_pcap, buffer_size, rank, startt, endd,'flows_assignment.csv','s38-eth1')
        # print("after serialize...")
        # print("s.cnt = {}".format(s.cnt))
        model, U, S, V = s.k_means(centeriods)
        summary_size = 0
        ips_len = 0

        d = Deserialize(model.cluster_centers_,U, S, V, rank)
        # print("after Deserialize...")

        labels = model.labels_
        # print("labels = {}".format(labels))
        counter = Counter(labels)
        cluster_centers = model.cluster_centers_
        #print("cluster_centers = {}".format(cluster_centers))
       
        my_dict = {}
        for label, count in counter.most_common(centeriods):
            my_dict[label] = count
        # print('my_dict = {}'.format(my_dict))

        f1 = csv.writer(open("s38_eth1_summary.csv",'w')) 
        f1.writerow(['key','val'])
        for center in cluster_centers:
            #print("shape of center = {}".format(center.shape))
            prediction = model.predict(center.reshape(1,12))
            # print("prediction = {}".format(prediction))
            if prediction[0] in my_dict:
                count1 = my_dict[model.predict(center.reshape(1,12))[0]]
                # print("center = {}, count = {}".format(center,count1))
               # d.dict[str(center)] = str(count1) 
                f1.writerow([str(center), str(count1)])
            else: 
                continue

       
        index_list = []
        #with open("Jaal_summary.txt",'w') as f3:
         #   for index in range(len(cluster_centers)):
                # print("cluster_centers[{}] = {}".format(index,cluster_centers[index].tolist()))
          #      center_number = model.predict(cluster_centers[index].reshape(1,rank))
           #     for ll in range(s.cnt):
                    #print("ll = {}".format(ll))
                    # print(U[ll])
            #        if ( model.predict(U[ll].reshape(1,rank))==center_number):
                        # print("found in = {}".format(ll))
             #           f3.write(str(ll) + str(s.normalized_matrix[ll]) + '\n')
               #         summary_size += s.tcp_len_vec[ll]
              #          ips_len += s.ip_len_vec[ll]
                #        break
                
        
        # print("index_list = {}".format(index_list))
        common = []
        att_pkts = 0
        false_positive = 0

        for label, count in counter.most_common(centeriods): 
            # print('%s: %d' % (letter, count))
            threshold = 13 #math.floor(centeriods/100)
            # print("threshold = {}".format(threshold))
            if count >= threshold:
                # print("attack detected for letter = {}".format(letter))
                att_pkts += count
                common.append(label)
        print("threshold = {}".format(threshold))
        print("attack packts detected = {}".format(att_pkts))

        total_attack_pkts =  buffer_size * .1 
        confidence = (att_pkts ) / (1.0 * total_attack_pkts) 
        avg_confidence += confidence /(1.0 * iterations)
        # data_reduction = 1 - ( centeriods / (1.0 * buffer_size) )
        if att_pkts > total_attack_pkts:
            false_positive += (att_pkts - total_attack_pkts)/(1.0 * total_attack_pkts)
            false_positive_rate += false_positive /(1.0 * iterations)
            confidence = 1
        print("total_attack_pkts = {}".format(total_attack_pkts))
        print("confidence = {}".format(confidence))
        print("false_positive = {}".format(false_positive))

        query_vector = np.ones(s.HEADER_FIELDS) * -1
        query_vector[s.SYN] = 1
        Jaal_diff_normal = []

        for i in range(centeriods):
            Jaal_diff_normal.append(d.jaal_diff(query_vector, d.packet_matrix[i,:]))

    avg_summary_size = summary_size /(1.0 * iterations)
    avg_total_raw_pkts_len = s.total_pkts_len /(1.0 * iterations)
    sum_tcp_len = sum(s.tcp_len_vec)
    avg_sum_tcp_len = sum_tcp_len /(1.0 * iterations)
    print("summary_size = {}, total_pkts_len = {}, ips_len = {}".format(summary_size,s.total_pkts_len, ips_len))
    print("avg_summary_size = {}, avg_total_raw_pkts_len = {}, avg_ips_len = {}".format(avg_summary_size,avg_total_raw_pkts_len, ips_len/(1*iterations)))
    print("avg_sum_tcp_len = {}".format(avg_sum_tcp_len))
    print("summary_size_percentage = {}".format(avg_summary_size * 100 /(1.0 * avg_sum_tcp_len) ))


    print("Average confidence = {}".format(avg_confidence * 100))
    print("false_positive_rate = {}".format(false_positive_rate * 100))
    data_reduction = 1 - ( centeriods / (1.0 * buffer_size) )
    # print("data_reduction = {}".format(data_reduction))

if __name__ == '__main__':
    main()
