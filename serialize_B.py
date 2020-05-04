import numpy as np
import dpkt 
import socket
import struct
from scipy.linalg import svd
from sklearn.cluster import KMeans
import csv
## creating summary
class Serialize_B:

    # total number of packet dimensions
    HEADER_FIELDS = 8
    # values to index int_matrix
    SPORT_INDEX = 0
    DPORT_INDEX = 1
    SEQ_INDEX = 2
    ACK_INDEX = 3
    WIN_INDEX = 4
    SUM_INDEX = 5
    SIP_INDEX = 6
    DIP_INDEX = 7

    # values to index binary_matrix
    DO_NOT_FRAGMENT = 0
    MORE_FRANGMENTS = 1
    FIN = 2
    SYN = 3
    RST = 4
    PUSH = 5
    ACK = 6
    URG = 7
    ECE = 8
    CWR = 9

    # Max values for normalization
    MAX_SPORT = 65531
    MAX_DPORT = 65416
    MAX_SEQ = 4293617831
    MAX_ACK = 4293617831
    MAX_WIN = 65535
    MAX_SUM = 65528
    MAX_S_IP = 3757027264
    MAX_D_IP = 3744647062

    SUM_SPORT = 15032259.0
    SUM_DPORT = 11601617.0
    SUM_SEQ = 1.16326734034e+12
    SUM_ACK = 8.43750017573e+11
    SUM_WIN = 7156369.0
    SUM_SUM = 16723034.0
    Mean_sport = 9.04004457597
    Var_sport = 5.89032807735
    Mean_dport = 7.21295014295
    Var_dport = 10.4633477918
    Mean_seq = 21.311610197
    Var_seq = 0.808271635652
    Mean_ack = 18.6989680258
    Var_ack = 47.9374887988
    Mean_win = 7.98511848813
    Var_win = 5.03428008098
    Mean_sum = 10.1207515544
    Var_sum = 0.939036547445

    def __init__(self, packet_source, buffer_size, rank, startt, endd, assignment_file,infc):
        print("Serialize_B...")
        """

        :param packet_source: The buffer of packets to summarize
        :param buffer_size: The size of the buffer referred in the paper as buffer size or n
        :param rank: intended rank of the summarized matrix
        """


        np.set_printoptions(suppress=True)
        self.packet_source = packet_source
        self.buffer_size = buffer_size
        self.rank = rank
        self.startt = startt
        self.endd = endd
        self.assignment_file = assignment_file
        self.infc = infc


        self.input_file = csv.DictReader(open(self.assignment_file))
        self.cnt = 0 ## counts number  of assigned flows
        self.flows_list = []
        for row in self.input_file:
            my_dict = dict(row)
            if my_dict['val'] == self.infc:
                self.flows_list.append(my_dict['key'])
                self.cnt += 1

        self.packet_matrix = self.return_original_matrix(self.buffer_size)
        self.normalized_matrix_1, self.pkts_num, self.ip_len_vec, self.tcp_len_vec, self.total_pkts_len = self.read_packets_2(startt, endd)
        self.normalized_matrix = self.normalized_matrix_1[0:self.pkts_num,:]


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

    def detrmine_max_values(self, packet_source):
      #This is a helper method. Gives an idea of the max values.

        with open(packet_source, 'rb') as f:
            pcap = dpkt.pcap.Reader(f)
            packet_matrix = np.zeros((self.buffer_size, self.HEADER_FIELDS))
            count = 0
            sport = 0
            dport = 0
            seq = 0
            ack = 0
            win = 0
            tcp_sum = 0
            urp = 0
            s_ip = 0
            d_ip = 0

            

            for time, packet in pcap:
                eth = dpkt.ethernet.Ethernet(packet)
                if isinstance(eth.data, dpkt.ip.IP) and isinstance(eth.data.data, dpkt.tcp.TCP):
                    ip = eth.data
                    
                    tcp = ip.data

                    if tcp.sport > sport:
                        sport = tcp.sport
                    if tcp.dport > dport:
                        dport = tcp.dport
                    if tcp.seq > seq:
                        seq = tcp.seq
                    if tcp.ack > ack:
                        ack = tcp.ack
                    if tcp.win > win:
                        win = tcp.win
                    if tcp.sum > tcp_sum:
                        tcp_sum = tcp.sum
                    if tcp.urp > urp:
                        urp = tcp.urp
                    if self.inet_to_str(ip.src) > s_ip:
                        s_ip = self.inet_to_str(ip.src)
                    if self.inet_to_str(ip.dst) > d_ip:
                        d_ip = self.inet_to_str(ip.dst)
                    count += 1

        print(count)
        s ="max sport={0} max dport={1} max seq={2} max ack={3} max win={4} max sum ={5} max urp={6} MAX_S_IP = {7} MAX_D_IP = {8}".format(sport, dport, seq, ack, win, tcp_sum, urp, s_ip, d_ip)
        print(s)



    def truncated_svd(self, rank, packet_matrix):
        try:
            U , S, V = np.linalg.svd(packet_matrix, full_matrices=False)
            # print("truncated_svd")
            return U[:, :self.rank], S[:self.rank], V[:self.rank, :]
        except np.linalg.LinAlgError:
            print("Something went wrong") 

    def calculate_statistics(self):
        m = self.return_original_matrix(500)
        for x in np.nditer(m, op_flags=['readwrite']):
            x[...] = 0 if x == 0 else np.log(x)

    def z_score(self,x,mean,var):
        # x = 0 if x == 0 else np.log(x)
        return (x-mean) / var

    def return_original_matrix(self, size):
        with open(self.packet_source, 'rb') as f:
            pcap = dpkt.pcap.Reader(f)
            packet_matrix = np.zeros((self.cnt, self.HEADER_FIELDS))
            count = 0
            for time, packet in pcap:
                eth = dpkt.ethernet.Ethernet(packet)
                if isinstance(eth.data, dpkt.ip.IP) and isinstance(eth.data.data, dpkt.tcp.TCP):

                    if count == self.cnt:
                        return packet_matrix

                    ip = eth.data
                    # Extract IP flags
                    do_not_fragment = bool(ip.off & dpkt.ip.IP_DF)
                    more_fragments = bool(ip.off & dpkt.ip.IP_MF)
                    fragment_offset = ip.off & dpkt.ip.IP_OFFMASK

                    tcp = ip.data

                    packet_matrix[count][self.SPORT_INDEX] = self.normalize(tcp.sport, self.MAX_SPORT)
                    packet_matrix[count][self.DPORT_INDEX] = self.normalize(tcp.dport, self.MAX_DPORT)
                    packet_matrix[count][self.SEQ_INDEX] = self.normalize(tcp.seq, self.MAX_SEQ)
                    packet_matrix[count][self.ACK_INDEX] = self.normalize(tcp.ack, self.MAX_ACK)
                    packet_matrix[count][self.WIN_INDEX] = self.normalize(tcp.win, self.MAX_WIN)
                    packet_matrix[count][self.SUM_INDEX] = self.normalize(tcp.sum, self.MAX_SUM)

                    count += 1


    def print_packet_details(self):
        with open(self.packet_source, 'rb') as f, open("disections_1000.txt", 'a') as f2:
            pcap = dpkt.pcap.Reader(f)
            packet_matrix = np.zeros((self.buffer_size, self.HEADER_FIELDS))
            count = 0
            for time, packet in pcap:
                eth = dpkt.ethernet.Ethernet(packet)
                if isinstance(eth.data, dpkt.ip.IP) and isinstance(eth.data.data, dpkt.tcp.TCP):

                    if count == self.buffer_size:
                        # return packet_matrix
                        # print packet_matrix
                        break
                    ip = eth.data
                    # Extract IP flags
                    do_not_fragment = bool(ip.off & dpkt.ip.IP_DF)
                    more_fragments = bool(ip.off & dpkt.ip.IP_MF)
                    fragment_offset = ip.off & dpkt.ip.IP_OFFMASK
                    tcp = ip.data
                    # print packet_matrix
                    p = ' IP:%d->%d (len=%d ttl=%d DF=%d MF=%d offset=%d FIN=%d SYN=%d RST=%d PUSH=%d ACK=%d URG=%d ECE=%d CWR=%d sport=%d dport=%d seq=%d ack=%d win=%d sum =%d urp=%d)\n' % \
                                            (self.inet_to_str(ip.src), self.inet_to_str(ip.dst), ip.len, ip.ttl, do_not_fragment, more_fragments,
                                            fragment_offset, (tcp.flags & dpkt.tcp.TH_FIN) != 0, (tcp.flags & dpkt.tcp.TH_SYN) != 0, (tcp.flags & dpkt.tcp.TH_RST) != 0,
                                             (tcp.flags & dpkt.tcp.TH_PUSH) != 0, (tcp.flags & dpkt.tcp.TH_ACK) != 0, (tcp.flags & dpkt.tcp.TH_URG) != 0, (tcp.flags & dpkt.tcp.TH_ECE) != 0, (tcp.flags & dpkt.tcp.TH_CWR) != 0,
                                             tcp.sport, tcp.dport, tcp.seq, tcp.ack, tcp.win, tcp.sum,tcp.urp)

                    f2.write(str(count) + p)
                    count+=1

    def reconstruct_matrix(self, U, S, V):
        U = np.append(U, np.zeros((len(U), self.rank)), axis=1)
        S = np.append(S, np.zeros(self.rank))
        V = np.append(V, np.zeros((self.rank, V.shape[1])), axis=0)
        packet_matrix = np.dot(U, np.dot(np.diag(S), V))
        return packet_matrix

    def k_means(self, num_clusters):
        U,S,V = self.truncated_svd(self.rank, self.normalized_matrix)
        model = KMeans(n_clusters=num_clusters, max_iter=1000, init='k-means++')
        return model.fit(U), U,S,V

    def read_packets_2(self, startt, endd):
        # buffer_size = 500
        with open(self.packet_source, 'rb') as f, open("packet_matrix.txt", 'w') as f2:
            pcap = dpkt.pcap.Reader(f)
            packet_matrix = np.zeros((self.buffer_size, 18))
            count = 0
            count2 = 0
            first = 0
            ip_len_vec = []
            tcp_len_vec = []
            total_pkts_len = 0
            flow1 = np.zeros(4)
            flows_found = 0
            jTry=0
            for time, packet in pcap:
                eth = dpkt.ethernet.Ethernet(packet)
                if jTry == endd :
                    packet_matrix_1 = packet_matrix[~np.all(packet_matrix == 0, axis=1)]
                    return packet_matrix_1, count2, ip_len_vec, tcp_len_vec, total_pkts_len
                    break
                jTry=jTry+1

                if isinstance(eth.data, dpkt.ip.IP) and isinstance(eth.data.data, dpkt.tcp.TCP):
                    ip1 = eth.data
                    tcp1 = ip1.data
                    source = ip1.src
                    destination = ip1.dst
                    flow1 = np.zeros(4)
                    flow1[0] = self.normalize(self.inet_to_str(source),self.MAX_S_IP)
                    flow1[1] = self.normalize(self.inet_to_str(destination), self.MAX_D_IP)
                    flow1[2] = self.normalize(tcp1.sport, self.MAX_SPORT)
                    flow1[3] = self.normalize(tcp1.dport, self.MAX_DPORT)

                    flow1[0] = self.inet_to_str(source)
                    flow1[1] = self.inet_to_str(destination)
                    flow1[2] = tcp1.sport
                    flow1[3] = tcp1.dport


                    flow_str = ''
                    flow_str = str(flow1[0]) + str(flow1[1]) + str(flow1[2]) + str(flow1[3])
                    
                    if flow_str in self.flows_list:
                        found = 1
                    else:
                        found = 0 

                    if count < startt:
                        count += 1
                    elif count >= startt and count < endd :
                        if found == 0:
                            continue
                        
                        
                        
                        flows_found += 1

                        ip = eth.data
                        # Extract IP flags
                        
                        do_not_fragment = bool(ip.off & dpkt.ip.IP_DF)
                        more_fragments = bool(ip.off & dpkt.ip.IP_MF)
                        fragment_offset = ip.off & dpkt.ip.IP_OFFMASK
                        tcp = ip.data

                        
                        total_pkts_len += ip.len
                        ip_len_vec.append(ip.len)
                        tcp_len_vec.append(len(tcp))
                        packet_matrix[count2][0] = self.normalize(tcp.sport, self.MAX_SPORT)
                        packet_matrix[count2][1] = self.normalize(tcp.dport, self.MAX_DPORT)
                        packet_matrix[count2][2] = self.normalize(tcp.seq, self.MAX_SEQ)
                        packet_matrix[count2][3] = self.normalize(tcp.ack, self.MAX_ACK)
                        packet_matrix[count2][4] = self.normalize(tcp.win, self.MAX_WIN)
                        packet_matrix[count2][5] = self.normalize(tcp.sum, self.MAX_SUM)
                        packet_matrix[count2][6] =  self.normalize( self.inet_to_str(ip.src), self.MAX_S_IP)
                        packet_matrix[count2][7] =  self.normalize(  self.inet_to_str(ip.dst), self.MAX_D_IP)
                        packet_matrix[count2][8] = do_not_fragment
                        packet_matrix[count2][9] = more_fragments
                        packet_matrix[count2][10] = (tcp.flags & dpkt.tcp.TH_FIN) != 0
                        packet_matrix[count2][11] = (tcp.flags & dpkt.tcp.TH_SYN) != 0
                        packet_matrix[count2][12] = (tcp.flags & dpkt.tcp.TH_RST) != 0
                
                        packet_matrix[count2][13] = (tcp.flags & dpkt.tcp.TH_PUSH) != 0
                        packet_matrix[count2][14] = (tcp.flags & dpkt.tcp.TH_ACK) != 0
                        packet_matrix[count2][15] = (tcp.flags & dpkt.tcp.TH_URG) != 0
                        packet_matrix[count2][16] = (tcp.flags & dpkt.tcp.TH_ECE) != 0
                        packet_matrix[count2][17] = (tcp.flags & dpkt.tcp.TH_CWR) != 0




                        f2.write(str(count2) + str(packet_matrix[count2]) + '\n')

                        count+=1
                        count2+=1
                    else:
                        return packet_matrix_1, count2, ip_len_vec, tcp_len_vec, total_pkts_len


    def get_truncated_binary_matrix(self):
        with open(self.packet_source, 'rb') as f:
            pcap = dpkt.pcap.Reader(f)
            binary_matrix = np.zeros((self.buffer_size, 10))
            count = 0

            for time, packet in pcap:
                eth = dpkt.ethernet.Ethernet(packet)
                if isinstance(eth.data, dpkt.ip.IP) and isinstance(eth.data.data, dpkt.tcp.TCP):
                    if count == self.buffer_size:
                        return self.truncated_svd(self.rank, binary_matrix)

                    ip = eth.data
                    # Extract IP flags
                    do_not_fragment = bool(ip.off & dpkt.ip.IP_DF)
                    more_fragments = bool(ip.off & dpkt.ip.IP_MF)

                    tcp = ip.data

                    binary_matrix[count][self.DO_NOT_FRAGMENT] = do_not_fragment
                    binary_matrix[count][self.MORE_FRANGMENTS] = more_fragments
                    binary_matrix[count][self.FIN] = (tcp.flags & dpkt.tcp.TH_FIN) != 0
                    binary_matrix[count][self.SYN] = (tcp.flags & dpkt.tcp.TH_SYN) != 0
                    binary_matrix[count][self.RST] = (tcp.flags & dpkt.tcp.TH_RST) != 0
                    binary_matrix[count][self.PUSH] = (tcp.flags & dpkt.tcp.TH_PUSH) != 0
                    binary_matrix[count][self.ACK] = (tcp.flags & dpkt.tcp.TH_ACK) != 0
                    binary_matrix[count][self.URG] = (tcp.flags & dpkt.tcp.TH_URG) != 0
                    binary_matrix[count][self.ECE] = (tcp.flags & dpkt.tcp.TH_ECE) != 0
                    binary_matrix[count][self.CWR] = (tcp.flags & dpkt.tcp.TH_CWR) != 0

                    count += 1

def main():
    plot_variance()

def p_var():
    path_to_pcap = "/home/basem/Desktop/Network Intrusion Detection/THomas_1/Tools/Jaal/second_test.pcap"
    x = [200,500,2000, 4000, 5000]
    for i in x:
        s = Serialize(path_to_pcap, i, 15)
        print(s.MAX_SPORT*s.var_sport)


def plot_rank_vs_variance():
    path_to_pcap = "/home/basem/Desktop/Network Intrusion Detection/THomas_1/Tools/Jaal/second_test.pcap"
    l = []
    x = range(1,19,1)

    for j in x:
        s = Serialize(path_to_pcap, 4000.0, j)
        model, S, V = s.k_means(1200)
        reconstructed_centers = s.reconstruct_matrix(model.cluster_centers_, S, V)
        # reconstructed_centers = model.cluster_centers_
        temp_list = []
        for i in range(len(reconstructed_centers)):
            temp_list += sum(model.labels_ == i) * [reconstructed_centers[i][s.SIP_INDEX]]
        var = np.var(temp_list)
        l.append(abs(var - s.var_sip))

    l = [i * s.MAX_S_IP for i in l]
    print("y={0}".format(l))
    print("x={0}".format(x))



def plot_signular_values():
    path_to_pcap = "/home/basem/Desktop/Network Intrusion Detection/THomas_1/Tools/Jaal/second_test.pcap"
    s = Serialize(path_to_pcap, 1000, 15)
    p = s.read_packets_2()
    U,S,V = np.linalg.svd(p, full_matrices=False)
    print("x={0}".format(range(1,19,1)))
    print("y={0}".format(list(S)))

def plot_variance():
    path_to_pcap = "/home/basem/Desktop/Network Intrusion Detection/THomas_1/Tools/Jaal/second_test.pcap"
    v = range(500,5000,250)
    for buff_size in v:
        s = Serialize(path_to_pcap, buff_size, 15)
        l = []
        x = range(10,70,5)
        for j in x:
            index = int((j/100.0) * buff_size)

            model, S, V = s.k_means(index)
            reconstructed_centers = s.reconstruct_matrix(model.cluster_centers_, S, V)
            temp_list = []
            for i in range(len(reconstructed_centers)):
                temp_list += sum(model.labels_ == i) * [reconstructed_centers[i][s.SPORT_INDEX]]
            var = np.var(temp_list)
            l.append(abs(var - s.var_sport) / s.var_sport)
        print("y_{0}={1}".format(buff_size,l))

def my_main():
    path_to_pcap= "/home/babde006/compined_40.pcap"
   # path_to_pcap = "/Users/tunguyen/Desktop/Tools/NIDS/Jaal/second_test.pcap"
    buffer_size = 4000
    rank = 12
    S=Serialize_B(path_to_pcap, buffer_size, rank, 0, 4000)
    #for i in range(10):
     #   startt = i * buffer_size
     #   endd = startt + buffer_size -1
     #   S=Serialize_B(path_to_pcap, buffer_size, rank, startt, endd)
     #   print("S.normalized_matrix = {}".format(S.normalized_matrix))
    # plot_variance()

if __name__ == '__main__':
    my_main()
