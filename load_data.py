import os
import csv
import process_tools as pt
import visualisation as vs
import numpy as np

"""
Load log file:
    
[0] timestamp of the end of a flow (te),
[1] duration of flow (td),
[2] source IP address (sa),
[3] destination IP (da), 
[4] source port (sp), 
[5] destination port (dp), 
[6] protocol (pr), 
[7] flags (flg), 
[8] forwarding status (fwd), 
[9] type of service (stos), 
[10] packets exchanged in the flow (pkt), 
[11] and their corresponding number of bytes (byt),
[12] background/blacklist/anomaly-spam task. (10^-5 % other task)
"""
time = 0
duration = 1
srcIP = 2
destIP = 3
srcport = 4
destport = 5
protocol = 6
flags = 7
fwd = 8
service = 9
npackets = 10
nbytes = 11
status = 12

#https://www.varonis.com/fr/blog/protocole-smb-explication-des-ports-445-et-139


def getLines(filename):
    with open(filename, "r") as csvfile:
        datareader = csv.reader(csvfile) #headers
        for row in datareader:
            yield row

"""
yield the dataset
"""
def training_data(file_path):
    csvFile = os.path.dirname(os.path.realpath(__file__)) + file_path

    return getLines(csvFile)


def load_yielded_data(data):
    srcIPs = {}
    for line in data:
        ### load the yielded data, break after first iteration ###
        for elem in line:
            if line[2] not in srcIPs:
                srcIPs[line[2]] = []
            
            srcIPs[line[2]].append(line)

            break

    return srcIPs

def save_Matrix(file, data_np_array):
    #save the np array into a file
    np.savetxt(file, data_np_array, delimiter=',')


def load_Matrix(file, mat_shape):
    # load array
    data = np.loadtxt(file, delimiter=',')
    data.reshape(mat_shape)
    # print the array
    return data    
    

"""
print in a file the potential blacklisted src IPs and the dest IPs that should not receive a packet
"""
def get_src_and_dest_blacklist_IPs(file):
    week_lines = training_data(file)
    line_batch = [None] * 100000
    line_batch[0] = next(week_lines)   # removes the first line which is the title of the columns (or a blank array)

    try:
        while True:
        ### load 100000 lines ###
            for i in range(100000):
                line_batch[i] = next(week_lines)

            srcIPs = load_yielded_data(line_batch)

            srcIPDict = {}
            destIPDict = {}
            for host in srcIPs:
                for line in srcIPs[host]:
                    if line[status] == 'blacklist':
                        if line[srcIP] in srcIPDict:
                            srcIPDict[line[srcIP]]['blacklist'] += 1
                        else:
                            srcIPDict[line[srcIP]] = {'IP': line[srcIP], 'blacklist':1, 'total_com':0}

                        if line[destIP] in destIPDict:
                            destIPDict[line[destIP]]['blacklist'] += 1
                        else:
                            destIPDict[line[destIP]] = {'IP': line[destIP], 'blacklist':1, 'total_com':0}
                    else :
                        if line[srcIP] not in srcIPDict:
                            srcIPDict[line[srcIP]] = {'IP': line[srcIP], 'blacklist':0, 'total_com':0}
                        if line[destIP] not in destIPDict:
                            destIPDict[line[destIP]] = {'IP': line[destIP], 'blacklist':0, 'total_com':0}

                    srcIPDict[line[srcIP]]['total_com'] += 1
                    destIPDict[line[destIP]]['total_com'] += 1

            for ip in srcIPDict:
                pt.blacklist_IP_saving(srcIPDict[ip], "src")
            
            for ip in destIPDict:
                pt.blacklist_IP_saving(destIPDict[ip], "dest")
                
    except:
        print("An error occured in get_src_and_dest_blacklist_IPs()")


"""
print in an number-of-occurence ordered way, the countries corresponding to the 
first 10k different IPs of blacklisted commnunications
"""
def get_suspicious_countries(file):
    week_lines = training_data(file)
    line_batch = [None] * 10000
    line_batch[0] = next(week_lines)   # removes the first line which is the title of the columns (or a blank array)

    suspicious_countries = {}
    blacklisted_IPs = set()

    while(len(blacklisted_IPs) < 10000):
        for i in range(10000):
            line_batch[i] = next(week_lines)

        load_yielded_data(line_batch)

        for line in line_batch:
            if line[status] == "blacklist":
                if not pt.is_company_IP(line[srcIP]):
                    blacklisted_IPs.add(line[srcIP])
                else:
                    if not pt.is_company_IP(line[destIP]):
                        blacklisted_IPs.add(line[destIP])
    
    for ip in blacklisted_IPs:
        pt.add_to_dict(suspicious_countries, pt.get_ip_location(ip))

    print({k: v for k, v in sorted(suspicious_countries.items(), key=lambda item: item[1])})
    
"""
plot the cumulative distribution for communications between 50 and 500 bytes of a given file
"""
def display_blacklist_communication_size(file):
    week_lines = training_data(file)
    line = next(week_lines)   # removes the first line which is the title of the columns (or a blank array)
    
    UDP = {}
    TCP = {}
    ICMP = {}

    num_UDP = 0
    num_TCP = 0
    num_ICMP = 0
    try:
        while line != None:
            line = next(week_lines)
            for elem in line:#load the yielded line
                break

            if line[protocol] == 'UDP':
                if line[status] == 'blacklist':
                    num_UDP += 1
                    pt.add_to_dict(UDP, int(line[nbytes]))

            elif line[protocol] == 'TCP':
                if line[status] == 'blacklist':
                    num_TCP += 1
                    pt.add_to_dict(TCP, int(line[nbytes]))
                
            elif line[protocol] == 'ICMP':
                if line[status] == 'blacklist':
                    num_ICMP += 1
                    pt.add_to_dict(ICMP, int(line[nbytes]))

    except:
        UDPprobas, scale = pt.cumul_dist_array(UDP, 50, 500, num_UDP)
        TCPprobas, scale = pt.cumul_dist_array(TCP, 50, 500, num_TCP)
        ICMPprobas, scale = pt.cumul_dist_array(ICMP, 50, 500, num_ICMP)
        vs.heatmap(["UDP", "TCP", "ICMP"], scale, [UDPprobas, TCPprobas, ICMPprobas], "Blacklisted Communications size - cumulative")


def display_blacklisted_duration(file):
    week_lines = training_data(file)
    line = next(week_lines)   # removes the first line which is the title of the columns (or a blank array)
    
    UDP = {}
    TCP = {}
    ICMP = {}

    num_UDP = 0
    num_TCP = 0
    num_ICMP = 0
    try:
        while line != None:
            line = next(week_lines)
            for elem in line:#load the yielded line
                break

            if line[protocol] == 'UDP':
                if line[status] == 'blacklist':
                    num_UDP += 1
                    pt.add_to_dict(UDP, float(line[duration]))

            elif line[protocol] == 'TCP':
                if line[status] == 'blacklist':
                    num_TCP += 1
                    pt.add_to_dict(TCP, float(line[duration]))

            elif line[protocol] == 'ICMP':
                if line[status] == 'blacklist':
                    num_ICMP += 1
                    pt.add_to_dict(ICMP, float(line[duration]))
    except:
        UDPprobas, scale = pt.cumul_dist_array(UDP, 0.0, 25.0, num_UDP, decimal=2)
        TCPprobas, scale = pt.cumul_dist_array(TCP, 0.0, 25.0, num_TCP, decimal=2)
        ICMPprobas, scale = pt.cumul_dist_array(ICMP, 0.0, 25.0, num_ICMP, decimal=2)
        vs.heatmap(["UDP", "TCP", "ICMP"], scale, [UDPprobas, TCPprobas, ICMPprobas],
                    "Blacklisted Communications duration - cumulative")

def display_blacklisted_flags(file):
    week_lines = training_data(file)
    line = next(week_lines)   # removes the first line which is the title of the columns (or a blank array)
    
    UDP = {}
    TCP = {}
    ICMP = {}

    oUDP = {}
    oTCP = {}
    oICMP = {}

    num_UDP = 0
    num_TCP = 0
    num_ICMP = 0
    try:
        while line != None:
            line = next(week_lines)
            for elem in line:#load the yielded line
                break

            if line[protocol] == 'UDP':
                if line[status] == 'blacklist':
                    num_UDP += 1
                    pt.add_to_dict(UDP, line[flags])
                else:
                    pt.add_to_dict(oUDP, line[flags])

            elif line[protocol] == 'TCP':
                if line[status] == 'blacklist':
                    num_TCP += 1
                    pt.add_to_dict(TCP, line[flags])
                else:
                    pt.add_to_dict(oTCP, line[flags])

            elif line[protocol] == 'ICMP':
                if line[status] == 'blacklist':
                    num_ICMP += 1
                    pt.add_to_dict(ICMP, line[flags])
                else:
                    pt.add_to_dict(oICMP, line[flags])
    except:
        vs.bar_plot_from_dict(UDP, "UDP blacklist-others flags", dict_data2=oUDP, lowerlimit=1)
        vs.bar_plot_from_dict(TCP, "TCP blacklist-others flags", dict_data2=oTCP, lowerlimit=1)
        vs.bar_plot_from_dict(ICMP, "ICMP blacklist-others flags", dict_data2=oICMP, lowerlimit=1)

        for flag in UDP:
            UDP[flag] = UDP[flag] / (num_UDP/100)
        vs.bar_plot_from_dict(UDP, "UDP blacklist flags percentage", lowerlimit=0)

        for flag in TCP:
            TCP[flag] = TCP[flag] / (num_TCP/100)
        vs.bar_plot_from_dict(TCP, "TCP blacklist flags percentage", lowerlimit=0)

        for flag in ICMP:
            ICMP[flag] = ICMP[flag] / (num_ICMP/100)
        vs.bar_plot_from_dict(ICMP, "ICMP blacklist flags percentage", lowerlimit=0)


def find_company_prefix(file):
    week_lines = training_data(file)
    line = next(week_lines)   # removes the first line which is the title of the columns (or a blank array)

    prefix = {}

    try:
        while line != None:
            line = next(week_lines)

            for elem in line:#load the yielded line
                break

            srcaddr = line[srcIP].split('.')
            destaddr = line[destIP].split('.')
            
            pt.add_to_dict(prefix, srcaddr[0]+"."+srcaddr[1]+".")
            pt.add_to_dict(prefix, destaddr[0]+"."+destaddr[1]+".")
            

    except:
        newdict = {k: v for k, v in prefix.items() if v > 10**7}
        print({k: v for k, v in sorted(newdict.items(), key=lambda item: item[1])})


def find_ok_ports(file):
    week_lines = training_data(file)
    line = next(week_lines)   # removes the first line which is the title of the columns (or a blank array)

    TCP = {}
    UDP = {}
    ICMP = {}

    try:
        while line != None:
            line = next(week_lines)

            for elem in line:#load the yielded line
                break
            
            if line[protocol] == "TCP":
                pt.add_to_dict(TCP, line[destport])
            elif line[protocol] == "UDP":
                pt.add_to_dict(UDP, line[destport])
            elif line[protocol] == "ICMP":
                pt.add_to_dict(ICMP, line[destport])
            

    except:
        pass
    finally:
        for dico in [TCP, UDP, ICMP]:
            newdict = {k: v for k, v in dico.items() if v > 10**4}
            print({k: v for k, v in sorted(newdict.items(), key=lambda item: item[1])})



if __name__ == '__main__':
    print("Uncomment the function that you want to execute (each might take 5-20mins)")
    file = '/dataset/URG-16/uniq/march.week3.csv'
    #get_src_and_dest_blacklist_IPs(file')
    #get_suspicious_countries(file')
    #display_blacklist_communication_size(file')
    #display_blacklisted_duration(file')
    #display_blacklisted_flags(file')
    #find_company_prefix(file)
    #find_ok_ports(file')