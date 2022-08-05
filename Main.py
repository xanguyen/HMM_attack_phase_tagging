# -*- coding: utf-8 -*-
"""
Created on Sun Nov 28 23:23:06 2021

@author: Xavier
"""

import numpy as np
import argparse
import sys
import load_data as ld
import process_tools as pt
import time

STATES = ['Clean', 'C&C', 'Recon', 'Lateral', 'Exfil', 'Botnet']

Clean = 0
C_C = 1
Recon = 2
Lateral = 3
Exfil = 4
Botnet = 5

OBSERVATIONS = ['ICMP_tunneling_out',
                'ICMP_tunneling_in',
                'ICMP_attack',
                'internal_com',
                'not_usual_port_protocol',
                'huge_payload_out',
                'huge_payload_in',
                'huge_payload',
                'port_scannig',
                'HIGH_suspicious_country',
                'Nothing',
                'unknown_internal_com',
                'LOW_not_usual_port_protocol',
                'unknown_huge_payload_out',
                'unknown_huge_payload_in',
                'unknown_huge_payload',
                'used_multiple_ports',
                'suspicious_country']

ICMP_tunneling_out = 0
ICMP_tunneling_in = 1
ICMP_attack = 2
internal_com = 3
not_usual_port_protocol = 4
huge_payload_out = 5
huge_payload_in = 6
huge_payload = 7
port_scannig = 8
HIGH_suspicious_country = 9
Nothing = 10
unknown_internal_com = 11
LOW_not_usual_port_protocol = 12
unknown_huge_payload_out = 13
unknown_huge_payload_in = 14
unknown_huge_payload = 15
used_multiple_ports = 16
suspicious_country = 17


def classify(features, src_ip, dest_ip, training_set=[], training_phase=False):
    real_state = None
    if training_phase:
        if training_set == []:#training phase, we are sure that there is no blacklisted com
            #However we still have to find what would be the observation if it was not in the training phase
            real_state = Clean
        else:
            priority = 2
            for event in training_set:
                if pt.is_company_IP(event[ld.srcIP]):
                    priority = 0
                    if pt.is_company_IP(event[ld.destIP]):
                        real_state = Lateral
                        break
                    elif event[ld.protocol] == "ICMP":
                        real_state = Exfil
                    elif pt.is_big_payload([event]) == pt.HIGH:
                        real_state = Exfil
                    else:
                        real_state = Botnet

                if pt.is_company_IP(event[ld.destIP]) and priority > 0:
                    priority = 1
                    if pt.is_big_payload([event]) < pt.HIGH:
                        real_state = Recon
                    else:
                        real_state = C_C
                else:
                    if priority > 1:
                        priority = 1
                        real_state = Recon

    max_f = 2
    features_sum = features[0] + features[1]
    for f in range(2, len(features)-1): #0 and 1 are already taken into consideration
        if features[f] > features[max_f]:
            max_f = f
        features_sum += features[f]

    if features[max_f] < 3 and features_sum < 4:
        return Nothing, real_state

    if features[0] >= pt.MEDIUM or features[1] >= pt.MEDIUM:
        if features[7] == 'ICMP':
            if pt.is_company_IP(src_ip):
                return ICMP_tunneling_out, real_state
            elif pt.is_company_IP(dest_ip):
                if features[4] == pt.HIGH:
                    return ICMP_tunneling_in, real_state
                return ICMP_attack, real_state #smurf attack, recon, Botnet, DOS

        
        if max_f == 2:
            return internal_com, real_state

        elif max_f == 3:
            return not_usual_port_protocol, real_state

        elif max_f == 4:
            if pt.is_company_IP(src_ip):
                return huge_payload_out, real_state
            elif pt.is_company_IP(dest_ip):
                return huge_payload_in, real_state
            else:
                return huge_payload, real_state

        elif max_f == 5: 
            return port_scannig, real_state

        elif max_f == 6:
            return HIGH_suspicious_country, real_state

    elif pt.is_company_IP(src_ip) and pt.is_company_IP(dest_ip):
        return unknown_internal_com, real_state
    else:
        max_f = 2
        features_sum = features[0] + features[1]
        for f in range(2, len(features)-1): #0 and 1 are already taken into consideration
            if features[f] > features[max_f]:
                max_f = f
            features_sum += features[f]
        if features[max_f] < 3 and features_sum < 4:
            return Nothing, real_state

        if max_f == 2:
            return unknown_internal_com, real_state

        elif max_f == 3:
            return LOW_not_usual_port_protocol, real_state

        elif max_f == 4:
            if pt.is_company_IP(src_ip):
                return unknown_huge_payload_out, real_state
            elif pt.is_company_IP(dest_ip):
                return unknown_huge_payload_in, real_state
            else:
                return unknown_huge_payload, real_state

        elif max_f == 5: 
            return used_multiple_ports, real_state

        elif max_f == 6:
            return suspicious_country, real_state

        else:
            print("should not happen")
            return Nothing, real_state



def get_observation_from_event_sequence(event_sequence, training_phase=False):
    timestamps = event_sequence[0][ld.time]
    
    #only need for the training phase
    training_set = []

    # load the yielded data to process it
    for event in event_sequence:
        for field in event:
            break


    ### --- group by src/dest IP --- ###
    srcIP_destIP_dict = {}

    best_features_sum = -1
    best_features = None

    for event in event_sequence:
        if (event[ld.srcIP]+"/"+event[ld.destIP]) in srcIP_destIP_dict:
            srcIP_destIP_dict[event[ld.srcIP]+"/"+event[ld.destIP]].append(event)
        else:
            srcIP_destIP_dict[event[ld.srcIP]+"/"+event[ld.destIP]] = [event]

        if training_phase :
            if event[ld.status] == 'blacklist':
                training_set.append(event)


    for ips in srcIP_destIP_dict:
        features = [0]*8

        features[0] = pt.is_blacklisted_src_IP(srcIP_destIP_dict[ips][0][ld.srcIP])
        features[1] = pt.is_blacklisted_dest_IP(srcIP_destIP_dict[ips][0][ld.destIP])
        features[2] = pt.internal_communication_trigger(srcIP_destIP_dict[ips][0][ld.srcIP], srcIP_destIP_dict[ips][0][ld.destIP])
        features[3] = pt.port_protocol_trigger(srcIP_destIP_dict[ips])
        features[4] = pt.is_big_payload(srcIP_destIP_dict[ips])
        features[5] = pt.port_scanning_flag(srcIP_destIP_dict[ips])
        #features[6] = pt.location_trigger(srcIP_destIP_dict[ips][0][ld.srcIP])
        features[7] = srcIP_destIP_dict[ips][0][ld.protocol]

        features_sum = features[0] + features[1]
        ### blacklisted src or dest IP ###
        if features[0] == pt.HIGH or features[1] == pt.HIGH:
            if training_phase: 
                observation, state = classify(features,
                                            srcIP_destIP_dict[ips][0][ld.srcIP],
                                            srcIP_destIP_dict[ips][0][ld.destIP],
                                            training_set=training_set, 
                                            training_phase=training_phase)
                return timestamps, observation, state

            for event in srcIP_destIP_dict[ips]:
                if event[ld.protocol] == 'ICMP':
                    if pt.is_company_IP(event[ld.srcIP]):
                        return timestamps, ICMP_tunneling_out
                    elif pt.is_company_IP(event[ld.destIP]):
                        if int(event[ld.nbytes]) > 100:
                            return timestamps, ICMP_tunneling_in
                        return timestamps, ICMP_attack #smurf attack, recon, Botnet, DOS

            max_f = 2
            for f in range(2, len(features)-1): #0 and 1 are already taken into consideration
                if features[f] > features[max_f]:
                    max_f = f
                features_sum += features[f]

            if max_f == 2:
                return timestamps, internal_com

            elif max_f == 3:
                return timestamps, not_usual_port_protocol

            elif max_f == 4:
                if pt.is_company_IP(srcIP_destIP_dict[ips][0][ld.srcIP]):
                    return timestamps, huge_payload_out
                elif pt.is_company_IP(srcIP_destIP_dict[ips][0][ld.destIP]):
                    return timestamps, huge_payload_in
                else:
                    return timestamps, huge_payload

            elif max_f == 5: 
                return timestamps, port_scannig

            elif max_f == 6:
                return timestamps, suspicious_country


        if features_sum > best_features_sum:
            best_features_sum = features_sum
            best_features = features

    
    observation, state = classify(features,
                                    srcIP_destIP_dict[ips][0][ld.srcIP],
                                    srcIP_destIP_dict[ips][0][ld.destIP],
                                    training_set=training_set,
                                    training_phase=training_phase)
    if training_phase:
        return timestamps, observation, state
    else:
        return timestamps, observation


def forward(V, a, b, initial_distribution):
    alpha = np.zeros((V.shape[0], a.shape[0]))
    alpha[0, :] = initial_distribution * b[:, V[0]]
 
    for t in range(1, V.shape[0]):
        for j in range(a.shape[0]):
            # Matrix Computation Steps
            #                  ((1x2) . (1x2))      *     (1)
            #                        (1)            *     (1)
            alpha[t, j] = alpha[t - 1].dot(a[:, j]) * b[j, V[t]]
 
    return alpha
 
def backward(V, a, b):
    beta = np.zeros((V.shape[0], a.shape[0]))
 
    # setting beta(T) = 1
    beta[V.shape[0] - 1] = np.ones((a.shape[0]))
 
    # Loop in backward way from T-1 to
    # Due to python indexing the actual loop will be T-2 to 0
    for t in range(V.shape[0] - 2, -1, -1):
        for j in range(a.shape[0]):
            beta[t, j] = (beta[t + 1] * b[:, V[t + 1]]).dot(a[j, :])
 
    return beta

# Learning part
# Function inspiration -> this implementation :
# #http://www.adeveloperdiary.com/data-science/machine-learning/derivation-and-implementation-of-baum-welch-algorithm-for-hidden-markov-model/
def baum_welch(O, a, b, initial_distribution, n_iter=100):
    M = a.shape[0]
    T = len(O)
    for n in range(n_iter):
        ###estimation step
        alpha = forward(O, a, b, initial_distribution)
        beta = backward(O, a, b)
        xi = np.zeros((M, M, T - 1))
        for t in range(T - 1):
            # joint probab of observed data up to time t @ transition prob * 
            #emisssion prob at t+1 @ joint probab of observed data from at t+1
            denominator = (alpha[t, :].T @ a * b[:, O[t + 1]].T) @ beta[t + 1, :]
            for i in range(M):
                numerator = alpha[t, i] * a[i, :] * b[:, O[t + 1]].T * beta[t + 1, :].T
                xi[i, :, t] = numerator / denominator
        gamma = np.sum(xi, axis=1)
        ### maximization step
        a = np.sum(xi, 2) / np.sum(gamma, axis=1).reshape((-1, 1))
        # Add additional T'th element in gamma
        gamma = np.hstack((gamma, np.sum(xi[:, :, T - 2], axis=0).reshape((-1, 1))))
        K = b.shape[1]
        denominator = np.sum(gamma, axis=1)
        for l in range(K):
            b[:, l] = np.sum(gamma[:, O == l], axis=1)
        b = np.divide(b, denominator.reshape((-1, 1)))
    return a, b

def argmax(lst):
    if len(lst) < 1:
        print("the list should contain at least one element")
        return

    index = 0
    for i in range(len(lst)):
        if lst[i] > lst[index]:
            index = i

    return index

# decoding/inference part
def viterbi(obs_seq, states, initial_prob, trans_mat, emission_mat):
    trellis = np.zeros( (len(states), len(obs_seq)) ) # hold prob. of each state given each obs.
    pointers = np.zeros( (len(states), len(obs_seq)) ) # hold backpointer to best prior state

    # Determine each hidden state's prob. at time 0...
    for s in range(len(states)):
        trellis[s][0] = initial_prob[s] * emission_mat[s][obs_seq[0]]

    # ...and afterwards, tracking each state's most likely prior state, k.
    for o in range(1, len(obs_seq)):
        for s in range(len(states)):
            k = argmax([trellis[k][o - 1] * trans_mat[k][s] * emission_mat[s][obs_seq[o]] for k in range(len(states))])
            trellis[s][o] = trellis[k][o - 1] * trans_mat[k][s] * emission_mat[s][obs_seq[o]]
            pointers[s][o] = k

    most_likely_state_sequence = list()
    k = argmax([trellis[k][len(obs_seq) - 1] for k in range(len(states))])  #The index of the best final state

    for o in range(len(obs_seq)-1, -1, -1):  #Backtrack from the last observation
        most_likely_state_sequence.insert(0, states[k])
        k = int(pointers[k][o])

    return most_likely_state_sequence

def training_matrix_computation_step(file):
    week_lines = ld.training_data(file)
    line_batch = [None] * 1000
    line_batch[0] = next(week_lines)   # removes the first line which is the title of the columns (or a blank array)

    timestamps = []
    observations = []
    states = []


    try:
        while True:
            ### load 1000 lines ###
            for i in range(1000):
                line_batch[i] = next(week_lines)

            timestamp, obs, state = get_observation_from_event_sequence(line_batch, training_phase=True)
            timestamps.append(timestamp)
            observations.append(obs)
            states.append(state)

    except: #end of the document, we might miss at most 1000 lines
        print("End of document or exception")
    
    A = np.zeros((len(STATES), len(STATES)))
    B = np.zeros((len(STATES), len(OBSERVATIONS)))
    state_tot = [len(STATES)] * len(STATES)

    # initiate the dictionnaries in case all case cannot be found in in dataset (highly probable)
    # initiate at 1 to prevent dividing by 0 at the end
    for S_t1 in range(len(STATES)):
        for S_t2 in range(len(STATES)):
            A[S_t1][S_t2] = 1

        for o in range(len(OBSERVATIONS)):
            B[S_t1][o] = 1

    for S_t in range(len(states)-1):
        A[states[S_t]][states[S_t+1]] += 1          #to build the N_{i,j}
        state_tot[states[S_t]] += 1                 #to build the N_i or M_i

        B[states[S_t]][observations[S_t]] += 1      #to build the M_{i,j}

    
    for i in range(len(STATES)):
        #compute the transition matrix: a_{i,j} = N_{i,j}/N_i
        for j in range(len(STATES)):
            A[i][j] = A[i][j]/state_tot[i]

        #compute the emission matrix: b_i(o_j) = M_{i,j}/M_i
        for j in range(len(OBSERVATIONS)):
            B[i][j] = B[i][j]/state_tot[i]


    return A, B

def eval_step(file, A, B, output_file):

    week_lines = ld.training_data(file)
    line_batch = [None] * 1000
    line_batch[0] = next(week_lines)   # removes the first line which is the title of the columns (or a blank array)

    timestamps = []
    observations = []

    try:
        while True:
            ### load 1000 lines ###
            for i in range(1000):
                line_batch[i] = next(week_lines)

            timestamp, obs = get_observation_from_event_sequence(line_batch)
            timestamps.append(timestamp)
            observations.append(obs)

    except:
        print("end of file or exception")

    guessed_states = viterbi(np.array(observations), np.array(STATES), np.array([1/6]*6), A, B)


    print("Saving the timestamps + state in :", output_file)
    my_file = open(output_file, 'w')
    for i in range(len(timestamps)):
        my_file.write(timestamps[i] + "\t" + guessed_states[i] + "\n")

    my_file.close()

        


def testing_step(file, A, B):

    week_lines = ld.training_data(file)
    line_batch = [None] * 1000
    line_batch[0] = next(week_lines)   # removes the first line which is the title of the columns (or a blank array)

    timestamps = []
    observations = []
    real_states = []

    #obs_dico = {}

    try:
        while True:
            ### load 1000 lines ###
            for i in range(1000):
                line_batch[i] = next(week_lines)

            timestamp, obs, real_state = get_observation_from_event_sequence(line_batch, training_phase=True)
            timestamps.append(timestamp)
            observations.append(obs)
            real_states.append(real_state)

            #pt.add_to_dict(obs_dico, obs)
    except:
        print("end of file or exception")

    guessed_states = viterbi(np.array(observations), np.array(range(len(STATES))), np.array([1/6]*6), A, B)

    confusion_matrix_like = np.zeros((len(STATES), len(STATES)))

    for i in range(len(guessed_states)):
        confusion_matrix_like[real_states[i]][guessed_states[i]] += 1
        

    print(confusion_matrix_like)
    #print(obs_dico)




if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Attack phases sequence building")
    parser.add_argument("--action", type=str)
    parser.add_argument("--dataset", "-in", type=str)
    parser.add_argument("--transition_matrix", "-A", type=str)
    parser.add_argument("--emission_matrix", "-B", type=str)
    parser.add_argument("--output_file", "-out", type=str)


    args = parser.parse_args()

    if len(sys.argv) < 2 or args.dataset==None:
        print("/!\\ TO RUN THE PROGRAM, ENTER AT LEAST THE DATASET IN THOSE PARAMETERS:")
        print("python3 Main.py --action train/test/eval --dataset path_to_dataset.csv --transition_matrix "
            "path_to_transition_matrix.csv --emission_matrix path_to_emission_matrix.csv --output_file output_file_path.txt")
        exit()

    A_file, B_file = args.transition_matrix, args.emission_matrix
    #load the blacklisted IPs
    pt.load_src_blacklist_IPs()
    pt.load_dest_blacklist_IPs()

    if (A_file != None and B_file == None) or (A_file == None and B_file != None):
        print("Please provide both A and B or train the model")


    ### --- Testing step --- ###

    if args.action == "test":
        if A_file == None or B_file == None:
            print("You need to input both a transition_matrix.csv and a emission_matrix.csv files")
            exit()

        A = ld.load_Matrix(A_file, (len(STATES), len(STATES)))
        B = ld.load_Matrix(B_file, (len(STATES), len(OBSERVATIONS)))

        print("start of the testing step...")
        start = time.time()
        testing_step(args.dataset, A, B)
        print("Testing step done in :" + str(round((time.time()-start)/60, 2)) + "min\n")


    ### --- Evaluation step --- ###

    elif args.action == "eval":
        if A_file == None or B_file == None:
            print("You need to input both a transition_matrix.csv and a emission_matrix.csv files")
            exit()

        A = ld.load_Matrix(A_file, (len(STATES), len(STATES)))
        B = ld.load_Matrix(B_file, (len(STATES), len(OBSERVATIONS)))

        output = args.output_file
        if output == None:
            output = "output.csv"

        print("start of the evaluation step...")
        start = time.time()
        eval_step(args.dataset, A, B, output)
        print("Evaluation step done in :" + str(round((time.time()-start)/60, 2)) + "min\n")


    ### --- Training step --- ###

    else:#args.action == "train" or None
        
        print("Start of the training step...")
        start = time.time()
        A, B = training_matrix_computation_step(args.dataset)
        if A_file == None or B_file == None:
            A_file = "A.csv"
            B_file = "B.csv"

        print("Saving A, B to :",A_file,",",B_file)

        ld.save_Matrix(A_file, A)
        ld.save_Matrix(B_file, B)

        print(A.round(decimals=3))
        print(B.round(decimals=3))

        print("Training done in :" + str(round((time.time()-start)/60, 2)) + "min\n")


