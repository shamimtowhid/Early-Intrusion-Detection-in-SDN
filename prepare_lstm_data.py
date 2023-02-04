import pandas as pd
import numpy as np
from tqdm import tqdm

from sklearn.preprocessing import StandardScaler

P = 6 # number of packets per sample
N = 5 # Only flows that have greater than N subflows/samples
n = 5 # take the first n subflows/samples per flow

lstm_path = "./lstm_data/packet_"+str(P)+"/n_"+str(n)+"/"

train_df = pd.read_csv("./train_test_data/train_"+str(P)+".csv")
test_df = pd.read_csv("./train_test_data/test_"+str(P)+".csv")


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


#X_train = X_train.reset_index(drop=True).to_numpy()
#X_test = X_test.reset_index(drop=True).to_numpy()

scaler = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_test = scaler.transform(X_test)

y_train = np.array(y_train)
y_test = np.array(y_test)
#import pdb;pdb.set_trace()


# creating data for LSTM
sample, feature = X_train.shape
sample_number = sample-(sample%n)
train_feature = np.zeros((sample_number//n, n, feature))
train_lbl = []
#import pdb;pdb.set_trace()
count = 0
for i in range(sample_number//n):
    for idx,j in enumerate(range(count, count+n)):
#        import pdb;pdb.set_trace()
        train_feature[i, idx] = X_train[j]
        count += 1
    train_lbl.append(y_train[j])


sample, feature = X_test.shape
sample_number = sample-(sample%n)
test_feature = np.zeros((sample_number//n, n, feature))
test_lbl = []
count = 0
for i in range(sample_number//n):
    for idx, j in enumerate(range(count,count+n)):
        test_feature[i, idx] = X_test[j]
        count += 1
    test_lbl.append(y_test[j])

train_lbl = np.array(train_lbl)
test_lbl = np.array(test_lbl)


# saving data for LSTM
np.save(lstm_path+"X_train_n_"+str(n)+".npy", train_feature)
np.save(lstm_path+"X_test_n_"+str(n)+".npy", test_feature)
np.save(lstm_path+"y_test_n_"+str(n)+".npy", test_lbl)
np.save(lstm_path+"y_train_n_"+str(n)+".npy", train_lbl)
