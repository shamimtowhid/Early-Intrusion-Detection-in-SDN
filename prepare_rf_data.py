import pandas as pd
import numpy as np
from tqdm import tqdm

#from sklearn.preprocessing import StandardScaler

P = 6 # number of packets per sample
N = 5 # Only flows that have greater than N subflows/samples
n = 5 # take the first n subflows/samples per flow

rf_path = "./packet_"+str(P)+"/n_"+str(n)+"/"
#rf_path = "/home/sharedrive/ids_dataset/early_detection/rf_data/"
#lstm_path = "/home/sharedrive/ids_dataset/early_detection/lstm_data/"

train_df = pd.read_csv("./train_test_data/train_"+str(P)+".csv")
test_df = pd.read_csv("./train_test_data/test_"+str(P)+".csv")

#print(train_df.shape)
#print(test_df.shape)
# feature engineering

# prepare protocol columns
one_hot_protocol = pd.get_dummies(train_df["protocol"])
train_df.drop("protocol", axis=1, inplace=True)
train_df["UDP_protocol"] = one_hot_protocol[17]
train_df["TCP_protocol"] = one_hot_protocol[6]
train_df["ICMP_protocol"] = one_hot_protocol[1]

one_hot_protocol = pd.get_dummies(test_df["protocol"])
test_df.drop("protocol", axis=1, inplace=True)
test_df["UDP_protocol"] = one_hot_protocol[17]
test_df["TCP_protocol"] = one_hot_protocol[6]
test_df["ICMP_protocol"] = one_hot_protocol[1]


features_col = ['UDP_protocol', 'TCP_protocol', 'ICMP_protocol', 'flow_duration', 'tot_fwd_pkt', 'tot_fwd_pkt_len', 'fwd_pkt_len_mean', 'pkt_per_second', 'byte_per_second', 'iat_mean', 'iat_std']
selected_col = features_col + ["flow_id", "new_flow_id"]

#X_train, y_train = train_df[selected_col], train_df["label"]
#X_test, y_test = test_df[selected_col], test_df["label"]

#X_train = pd.DataFrame(columns=features_col)
y_train = []
res = train_df.groupby(['new_flow_id'])
super_x = []
for tmp in tqdm(res): # tmp : tuple (new_flow_id, DataFrame)
    tmp_id, tmp_df = tmp
    tmp_df = tmp_df.sort_values(by=['flow_id']).reset_index(drop=True)
    if tmp_df.shape[0]>=N:
        for idx in range(n):
            #X_train = pd.concat([X_train, tmp_df.loc[idx, features_col]], axis=0, join='outer')
            super_x.append(tmp_df.loc[idx, features_col])
            y_train.append(tmp_df.loc[idx, "label"])
#    elif tmp_df.shape[0]>=n: # this block is for balancing data with D5
#        for idx in range(n):
#            super_x.append(tmp_df.loc[idx, features_col])
#            y_train.append(tmp_df.loc[idx, "label"])

X_train = pd.concat(super_x, axis=1).transpose()
#import pdb;pdb.set_trace()
#X_test = pd.DataFrame(columns=features_col)
y_test = []
res = test_df.groupby(['new_flow_id'])
super_x = []
for tmp in tqdm(res): # tmp : tuple (new_flow_id, DataFrame)
    tmp_id, tmp_df = tmp
    tmp_df = tmp_df.sort_values(by=['flow_id']).reset_index(drop=True)
    if tmp_df.shape[0]>=N:
        for idx in range(n):
            #X_test = pd.concat([X_test, tmp_df.loc[idx, features_col]], axis=0, join='outer')
            super_x.append(tmp_df.loc[idx, features_col])
            y_test.append(tmp_df.loc[idx, "label"])
#    elif tmp_df.shape[0]>=n: # this block is for balancing data with D5
#        for idx in range(n):
#            super_x.append(tmp_df.loc[idx, features_col])
#            y_test.append(tmp_df.loc[idx, "label"])

X_test = pd.concat(super_x, axis=1).transpose()

#scaler = StandardScaler()
#X_train = scaler.fit_transform(X_train)
#X_test = scaler.transform(X_test)

y_train = np.array(y_train)
y_test = np.array(y_test)

# saving data for random forest
np.save(rf_path+"X_train_n_"+str(n)+".npy", X_train)
np.save(rf_path+"X_test_n_"+str(n)+".npy", X_test)
np.save(rf_path+"y_test_n_"+str(n)+".npy", y_test)
np.save(rf_path+"y_train_n_"+str(n)+".npy", y_train)
