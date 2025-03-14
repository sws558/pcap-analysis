import os
from scapy.all import *
import pandas as pd
import numpy as np
import torch
import torchvision.transforms as transforms
from torch.utils.data import Dataset, DataLoader
from app.model.model_1024 import ResNet50

PACKET_NUM_PER_SESSION = 30
PACKET_LEN = 300

class DealDataset(Dataset):
    """
        读取数据、初始化数据
    """
    def __init__(self, file_path, transform, size):
        train_set = self.load_data(file_path, size) # 其实也可以直接使用torch.load(),读取之后的结果为torch.Tensor形式
        self.train_set = train_set
        self.transform = transform

    def __getitem__(self, index):

        img = self.train_set[index]
        if self.transform is not None:
            img = self.transform(img)
        return img

    def __len__(self):
        return len(self.train_set)


    def load_data(self, file_path, size):
        """
            data_folder: 文件目录
            data_name： 数据文件名
            label_name：标签数据文件名
        """
        pcap_len = len(rdpcap(file_path))
        with open(file_path, 'rb') as imgpath:
            x_train = np.frombuffer(
                imgpath.read(), np.uint8, offset=16)
            x_train = x_train.reshape(int(len(x_train)/(size*size)), size, size)   #这里的大小记得改
        return x_train

def read_batch(data_raw):
    # data_raw = np_data["data"]  # 多分类
    # data_raw = data_raw.tolist()

    data_arr = []
    for i in range(len(data_raw)):
        data_arr.append(data_raw[i]["data"])

    if len(data_arr) == 0:
        print("read_batch none")
        return None

    pcapdata = np.array(data_arr)
    # print(pcapdata)
    pcapdata = pcapdata[:, :PACKET_NUM_PER_SESSION, :PACKET_LEN] * 255

    pcapdata_reshape = pcapdata.reshape((-1, PACKET_NUM_PER_SESSION, PACKET_LEN))

    return pcapdata_reshape

def init_model(model_path):
    model = ResNet50()
    model.load_state_dict(torch.load(model_path)["model_state_dict"])
    model.cuda()
    model.eval()

    return model

def predict(weight_path, pcap_filepath):
    # transform = transforms.ToTensor()
    model = init_model(weight_path)#resnet50
    traindataset = DealDataset(pcap_filepath, transforms.ToTensor(), 32)
    trainloader = DataLoader(traindataset, batch_size=32)
    # X = read_batch(np_data)
    # np_data = np.array(np_data)
    # X = transform(np_data)
    for data in trainloader:
        predictions = model(data)
        predicted_labels = np.argmax(predictions, axis=1)
        predicted_labels = predicted_labels.astype(np.int64)
        predicted_labels = predicted_labels.tolist()
        print(predicted_labels)

if __name__ == "__main__":
    model_path = "./app/model/save_model/checkpoint_model_best.pth"
    pcap_filepath = "store/pcap/vdnwhx9qlp.pcap"
    predict(model_path, pcap_filepath)