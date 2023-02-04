import os
import sys
from tqdm import tqdm

import pandas as pd
import numpy as np
from scapy.all import *


#FLOW_DURATION = 1 #seconds
PCKT_NUMBER = 6
UDP_DURATION = 400 #seconds
LABEL = "benign"

DIR_PATH = "./benign/"
DATASET_PATH = "./dataset_"+str(PCKT_NUMBER)+".csv"
MIN_PCKT = 2

PCKT_CONTAINER = {}   # { flow_id: [pckt_list]  }
TIMESTAMP = {}        # {flow_id: timestamp }
#FLOW_TIME = {}        # {flow_id: timestamp}
FLOW_COUNTER = {}     # {flow_id: counter}
SUB_FLOW_COUNTER = {} # {flow_id: counter}
FEATURES = []         # [{ flow_id, protocol, bytes_received in last 1s
                      # packet received in last 1s, avg pckt size in last 1s, Label}]


def process_pcap(fpath, file_id):
    #print(f"Opening {fpath}")

    global FEATURES, PCKT_CONTAINER, FLOW_COUNTER, TIMESTAMP, SUB_FLOW_COUNTER

    cap = PcapNgReader(fpath)

    for pkt_num, pkt in enumerate(cap):
        layers = pkt.layers()

        if type(IP()) in layers: 
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            protocol = str(pkt[IP].proto)
            if protocol=="6" or protocol=="17" or protocol=="1": # TCP(6), UDP(17), ICMP(1)
                if protocol == "1":
                    sport = str(0)
                    dport = str(0)
                else:
                    sport = str(pkt[IP].sport)
                    dport = str(pkt[IP].dport)

                #print(f"Packet Number: {pkt_num+1}, Src IP: {src_ip},\
                #        Dst IP: {dst_ip}, Protocol: {protocol},\
                #        Src Port: {sport}, Dst Port: {dport}")
                #import pdb;pdb.set_trace()

                fwd_id = src_ip+"_"+dst_ip+"_"+sport+"_"+dport+"_"+protocol
                bwd_id = dst_ip+"_"+src_ip+"_"+dport+"_"+sport+"_"+protocol

                if fwd_id in PCKT_CONTAINER.keys():
                    check_flow_termination(pkt, fwd_id, protocol, file_id)
#                    calculate_features(pkt, fwd_id, protocol)
                elif bwd_id in PCKT_CONTAINER.keys():
                    check_flow_termination(pkt, bwd_id, protocol, file_id)
#                    calculate_features(pkt, bwd_id, protocol)
                else:
                    if fwd_id in FLOW_COUNTER.keys():
                        PCKT_CONTAINER[fwd_id] = [pkt]
                        TIMESTAMP[fwd_id] = pkt.time
                    elif bwd_id in FLOW_COUNTER.keys():
                        PCKT_CONTAINER[bwd_id] = [pkt]
                        TIMESTAMP[bwd_id] = pkt.time
                    else:
                        FLOW_COUNTER[fwd_id] = 1
                        SUB_FLOW_COUNTER[fwd_id] = 1
                        PCKT_CONTAINER[fwd_id] = [pkt]
                        TIMESTAMP[fwd_id] = pkt.time

                    #PCKT_CONTAINER[fwd_id] = [pkt]
                    #import pdb;pdb.set_trace()
                    #TIMESTAMP[fwd_id] = pkt.time
                    #if fwd_id not in FLOW_COUNTER.keys() and bwd_id not in FLOW_COUNTER.keys():
                    #    FLOW_COUNTER[fwd_id] = 1
                    #if fwd_id not in SUB_FLOW_COUNTER.keys() and bwd_id not in SUB_FLOW_COUNTER.keys():
                    #    SUB_FLOW_COUNTER [fwd_id] = 1
                    #if fwd_id not in FLOW_TIME.keys():
                    #    FLOW_TIME[fwd_id] = pkt.time
                    #TCP_TIMESTAMP[fwd_id] = pkt.time

    # save the rest of the features once all the pckts are traversed
    for f_id in list(PCKT_CONTAINER.keys()):
        protocol = f_id.split("_")[-1]
        calc_features(PCKT_CONTAINER[f_id], f_id, protocol, file_id)
        SUB_FLOW_COUNTER[f_id] += 1
        
#        features={}
#        features["flow_id"] = f_id + "_" + str(TIMESTAMP[f_id])
#        features["protocol"] = protocol
#        features["pckt_received"] = len(PCKT_CONTAINER[f_id]) 
#        byte = 0
#        for pckt in PCKT_CONTAINER[f_id] :
#            byte+=len(pckt)
#        features["byte_received"] = byte
#        features["avg_pckt_size"]=byte/len(PCKT_CONTAINER[f_id])
#        features["label"] = LABEL
#        FEATURES.append(features)
        #del PCKT_CONTAINER[f_id]
        #del TIMESTAMP[f_id]
        #del FLOW_COUNTER[f_id]
        #del SUB_FLOW_COUNTER[f_id]

    # saving features to file here to avoid overflow of memory
    if os.path.exists(DATASET_PATH):
        df = pd.read_csv(DATASET_PATH) 
        df2 = pd.DataFrame(FEATURES)
        df = pd.concat([df,df2], axis=0, join='outer') # doing append using concat method
        df.to_csv(DATASET_PATH, index=False)
    else:
        df = pd.DataFrame(FEATURES)
        df.to_csv(DATASET_PATH, index=False)

    # empty the global variables
    PCKT_CONTAINER = {}   # { flow_id: [pckt_list]  }
    TIMESTAMP = {}        # {flow_id: timestamp }
    #FLOW_TIME = {}        # {flow_id: timestamp}
    FLOW_COUNTER = {}
    SUB_FLOW_COUNTER = {}
    FEATURES = []         # [{ flow_id, protocol, bytes_received in last 1s

def check_flow_termination(pkt, flow_id, protocol, file_id):
    # termination in 2 ways 
    # 1. flow_duration is complete
    # 2. TCP FIN is activated or UDP duration is complete
    if len(PCKT_CONTAINER[flow_id])<PCKT_NUMBER: # flow duration is not complete
        PCKT_CONTAINER[flow_id].append(pkt)
    
    else: # pckt count is complete
        calc_features(PCKT_CONTAINER[flow_id], flow_id, protocol, file_id)
        SUB_FLOW_COUNTER[flow_id] += 1
        del PCKT_CONTAINER[flow_id]
        return

    if protocol == "6": # check FIN for TCP
        FIN = 0x01
        ACK = 0x10
        FLAGS = pkt['TCP'].flags
        if (FLAGS & FIN) and (FLAGS & ACK): # FIN ACK activated
            #if len(PCKT_CONTAINER[flow_id])>=PCKT_NUMBER:
            calc_features(PCKT_CONTAINER[flow_id], flow_id, protocol, file_id)
            FLOW_COUNTER[flow_id] += 1
            SUB_FLOW_COUNTER[flow_id] = 1
            del PCKT_CONTAINER[flow_id]
            #del FLOW_TIME[flow_id]

    elif protocol == "17": # check flow duration for UDP
        #if len(PCKT_CONTAINER[flow_id])>=PCKT_NUMBER:
        #calc_features(PCKT_CONTAINER[flow_id], flow_id, protocol)
        current_time = pkt.time
        duration = current_time - TIMESTAMP[flow_id]
        if duration >= UDP_DURATION:
            calc_features(PCKT_CONTAINER[flow_id], flow_id, protocol, file_id)
            FLOW_COUNTER[flow_id] += 1
            SUB_FLOW_COUNTER[flow_id] = 1
            del PCKT_CONTAINER[flow_id]
            #del FLOW_TIME[flow_id]


def calc_features(pkt_list, flow_id, protocol, file_id):
#    print(f"Calculating Features for {flow_id}")
    if len(pkt_list)>MIN_PCKT:
        # src_ip_dst_ip_src_port_dst_port_protocol_flow_counter_subflow_counter_file_id
        f_id_to_save = flow_id + "_" + str(FLOW_COUNTER[flow_id]) + "_" + str(SUB_FLOW_COUNTER[flow_id]) + "_" +file_id
        feat_dict = {"flow_id": f_id_to_save, "protocol": int(protocol)}

        flow_duration = pkt_list[-1].time - TIMESTAMP[flow_id]
        feat_dict["flow_duration"] = float(flow_duration)

        fwd_pkt_features = calc_fwd_pkt_features(pkt_list, flow_id)
        feat_dict["tot_fwd_pkt"] = fwd_pkt_features[0]
        feat_dict["tot_fwd_pkt_len"] = fwd_pkt_features[1]
        feat_dict["fwd_pkt_len_mean"] = fwd_pkt_features[2]

        flow_features = calc_flow_features(pkt_list, flow_duration)
        feat_dict["pkt_per_second"] = flow_features[0]
        feat_dict["byte_per_second"] = flow_features[1]
        feat_dict["iat_mean"] = flow_features[2]
        feat_dict["iat_std"] = flow_features[3]

        feat_dict["label"] = LABEL
        #print(feat_dict)
        FEATURES.append(feat_dict)


def calc_flow_features(pkt_list, flow_duration):
    pkt_per_second = flow_duration/len(pkt_list)

    pkt_byte = 0
    iat = []
    for i, pkt in enumerate(pkt_list):
        pkt_byte += len(pkt)
        if i==0:
            iat.append(0)
            prev_time = pkt.time
        else:
            iat.append(float(pkt.time-prev_time))
            prev_time = pkt.time
    byte_per_second = flow_duration/pkt_byte
    iat_mean = np.mean(iat)
    iat_std = np.std(iat)

    return pkt_per_second, byte_per_second, iat_mean, iat_std


def calc_fwd_pkt_features(pkt_list, flow_id):
    src_ip = flow_id.split("_")[0]
    fwd_pkt_count = 0
    fwd_pkt_len = 0
    count = 0
    fwd_pkt_len_mean = []
    for pkt in pkt_list:
        if pkt[IP].src == src_ip:
            count += 1
            fwd_pkt_count += 1
            fwd_pkt_len += len(pkt)
            fwd_pkt_len_mean.append(len(pkt))
    if count==0:
        return 0, 0, 0
    else:
        return fwd_pkt_count, fwd_pkt_len, np.mean(fwd_pkt_len_mean)

#def calculate_features(pkt, flow_id, protocol):
#    if pkt.time-TIMESTAMP[flow_id]<FLOW_DURATION:
#        PCKT_CONTAINER[flow_id].append(pkt)
#    else:
        # calc feature
        # change the TIMESTAMP of this flow
        # del pckt container [flow_id]
#        features={}
#        features["flow_id"] = flow_id + "_" + str(TIMESTAMP[flow_id])
#        features["protocol"] = protocol
#        features["pckt_received"] = len(PCKT_CONTAINER[flow_id]) 
#        byte = 0
#        for pckt in PCKT_CONTAINER[flow_id] :
#            byte+=len(pckt)
#        features["byte_received"] = byte
#        features["avg_pckt_size"]=byte/len(PCKT_CONTAINER[flow_id])
#        features["label"] = LABEL
#        FEATURES.append(features)

        #TIMESTAMP[flow_id] = PCKT_CONTAINER[flow_id][-1].time
#        del PCKT_CONTAINER[flow_id]
#        del TIMESTAMP[flow_id]





if __name__ == "__main__":
    filenames = os.listdir(DIR_PATH)

    for i, fname in tqdm(enumerate(filenames)):
        process_pcap(DIR_PATH+fname, str(i))
