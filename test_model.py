from sklearn.metrics import confusion_matrix
from sklearn.metrics import classification_report
import os
import pathlib
import pickle
import subprocess

import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler

from app import app
from app.model.malware_type_class import ModelWang


def dump_pickle(obj, pickle_file):
    with open(pickle_file, 'wb') as f:
        pickle.dump(obj, f)


def load_pickle(pickle_file):
    with open(pickle_file, 'rb') as f:
        return pickle.load(f)


dataset_dir = "./data/"
malware_type_model = "./app/model/save_model/_300_30_30_malware_type.hdf5"
malware_normal_model = "./app/model/save_model/_300_30_normal_malware.hdf5"
dataset_file = "/root/opt/analysis/data/dataset.pkl"
labels = ["Benign", "Adware", "SMS", "Scareware", "Ransomware"]  # 二分类
# labels = ["Adware", "SMS", "Scareware", "Ransomware"]
labels_to_malware_type = {
    "Benign": 0,  # 二分类：0
    "Adware": 1,  # 二分类：1
    "SMS": 2,  # 二分类：1
    "Scareware": 3,  # 二分类：1
    "Ransomware": 0  # 二分类：1
}

labels_to_malware_normal = {
    "Benign": 0,  # 二分类：0
    "Adware": 1,  # 二分类：1
    "SMS": 1,  # 二分类：1
    "Scareware": 1,  # 二分类：1
    "Ransomware": 1  # 二分类：1
}


def process_data():
    # TODO 需要手动预处理 # 下完数据叫我
    model_HANDLE = ModelWang(weights_path=malware_type_model, num_classes=4)

    dataset_path = pathlib.Path(dataset_dir)

    dataset = {}
    for label in labels:
        dir = dataset_path / label / "pcaps/pkt2flow.out/tcp_syn/"
        x_test = np.array([]).reshape(0, 30, 300)

        for file in dir.rglob("*.pcap"):
            X = model_HANDLE.process_data(str(file))
            if X is None:
                continue
            x_test = np.vstack([x_test, X])

        dataset[label] = x_test
    dump_pickle(dataset, dataset_file)


def evaluate_data():

    dataset: dict = load_pickle(dataset_file)
    model_HANDLE = ModelWang(weights_path=malware_normal_model, num_classes=2)  # 二分类
    # model_HANDLE = ModelWang(weights_path=malware_type_model, num_classes=4) # 四分类
    y_pred = []
    y_true = []
    for label in labels:
        # if label in ["Ransomware", "Scareware", "SMS"]:
        #     continue 
        if label == "Benign":
            dataset[label] = dataset[label][:500]
        pred = model_HANDLE.model.predict(dataset[label])
        pred = np.argmax(pred, axis=1)
        y = np.full(len(pred), labels_to_malware_normal[label])
        y_true.append(y)
        y_pred.append(pred)

    # y_pred = np.argmax(y_pred, axis=1)

    y_true = np.concatenate(y_true)
    y_pred = np.concatenate(y_pred)
    print(confusion_matrix(y_true, y_pred))
    print(classification_report(y_true, y_pred, labels=np.unique(y_pred), zero_division=0))


if __name__ == "__main__":
    # 二选一
    # process_data()
    evaluate_data()
