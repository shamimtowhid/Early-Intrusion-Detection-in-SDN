import pandas as pd
import numpy as np
from tqdm import tqdm
from sklearn.model_selection import train_test_split

N = 6
path = "/home/sharedrive/ids_dataset/early_detection/dataset_"+str(N)+".csv"

df = pd.read_csv(path)
#print(df[ids.isin(ids[ids.duplicated()])].sort_values("flow_id"))
df = df.drop_duplicates(subset=['flow_id']).reset_index(drop=True)

print(df.shape)
print(df["flow_id"].nunique())
#import pdb;pdb.set_trace()

ids = df["flow_id"]
labels = df["label"]

# src_ip_dst_ip_src_port_dst_port_protocol_flow_id_subflow_id_file_id
flow_id = [] # src_ip_dst_ip_src_port_dst_port_protocol_flow_id_file_id
label = []

df["new_flow_id"] = "None"
for i in tqdm(range(len(ids))):
    f_id = ids[i]
    id_parts = f_id.split("_")
    del id_parts[6] # 6 is the index of subflow_id
    new_id = "_".join(id_parts)
    df.loc[i,"new_flow_id"] = new_id # adding new column to the dataframe
    if new_id not in flow_id:
        flow_id.append(new_id)
        label.append(labels[i])

print(len(flow_id))
print(len(label))
# imbalanced split
X_train, X_test, y_train, y_test = train_test_split(flow_id, label, test_size=0.3, random_state=42, stratify=label)

# Data balancing
#np_flow_id = np.array(flow_id)
#np_label = np.array(label)

#attack_lbl = np_label[np_label=='attack']
#benign_lbl = np_label[np_label=='benign']

#attack_flow_id = np_flow_id[np_label=='attack']
#benign_flow_id = np_flow_id[np_label=='benign']

#if len(attack_flow_id)>len(benign_flow_id):
#    random_index = np.random.choice(np.arange(len(attack_flow_id)), len(benign_flow_id))
#    sampled_attack_flow_id = attack_flow_id[random_index]
#    sampled_attack_label = attack_lbl[random_index]
#    balanced_flow_id = sampled_attack_flow_id.tolist() + benign_flow_id.tolist()
#    balanced_label = sampled_attack_label.tolist() + benign_lbl.tolist()
#else:
#    random_index = np.random.choice(np.arange(len(benign_flow_id)), len(attack_flow_id))
#    sampled_benign_flow_id = benign_flow_id[random_index]
#    sampled_benign_label = benign_lbl[random_index]
#    balanced_flow_id = sampled_benign_flow_id.tolist() + attack_flow_id.tolist()
#    balanced_label = sampled_benign_label.tolist() + attack_lbl.tolist()
#import pdb;pdb.set_trace()

#print(len(balanced_flow_id))
#print(len(balanced_label))
#X_train_blnc, X_test_blnc, y_train_blnc, y_test_blnc = train_test_split(balanced_flow_id, balanced_label, test_size=0.3, random_state=42, stratify=balanced_label)

X_train = pd.DataFrame(X_train, columns=["new_flow_id"])
#X_train_blnc = pd.DataFrame(X_train_blnc, columns=["new_flow_id"])
X_test = pd.DataFrame(X_test, columns=["new_flow_id"])
#X_test_blnc = pd.DataFrame(X_test_blnc, columns=["new_flow_id"])

train_df = df.merge(X_train, how='inner', on='new_flow_id')
#train_df = train_df.drop(["new_flow_id"], axis=1)
test_df = df.merge(X_test, how='inner', on='new_flow_id')
#test_df = test_df.drop(["new_flow_id"], axis=1)


#balanced_train_df = df.merge(X_train_blnc, how='inner', on='new_flow_id')
#balanced_train_df = balanced_train_df.drop(["new_flow_id"], axis=1)
#balanced_test_df = df.merge(X_test_blnc, how='inner', on='new_flow_id')
#balanced_test_df = balanced_test_df.drop(["new_flow_id"], axis=1)

train_df.to_csv("./data_vary_N/train_test_data/train_"+str(N)+".csv", index=False)
test_df.to_csv("./data_vary_N/train_test_data/test_"+str(N)+".csv", index=False)

#balanced_train_df.to_csv("./balanced_train.csv", index=False)
#balanced_test_df.to_csv("./balanced_test.csv", index=False)
