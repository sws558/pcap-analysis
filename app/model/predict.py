import os
import gzip
from array import *
import numpy as np
import pandas as pd
import binascii
from PIL import Image
from scapy.all import RawPcapNgReader
from app.extract_tls import pp_pcap
import torch
import torch.nn.functional as F
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
        with gzip.open(file_path, "rb") as imgpath:
        # pcap_len = len(rdpcap(file_path))
        # with open(file_path, 'rb') as imgpath:
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
    model.load_state_dict(torch.load(model_path, map_location=torch.device('cpu'))["model_state_dict"])
    # model.cuda()
    model.eval()

    return model

def predict_vpn(weight_path, pcap_flpath):
    csv_filepath, pcap_filepath = pp_pcap(pcap_flpath)
    # fh_list = getMatrixfrom_pcap(pcap_flpath, 32)
    fh_list = getMatrixfrom_pcap(pcap_filepath, 32)
    gz_flname = pcap_flpath.split(".")[0]
    resolve_input(fh_list, gz_flname)
    dataset = DealDataset("{}.gz".format(gz_flname), transform=transforms.ToTensor(), size=32)
    data_loader = DataLoader(dataset, batch_size=128)
    model = init_model(weight_path)
    model.eval()
    pred_list = []
    with torch.no_grad():
        for data in data_loader:
            # data = data.cuda()
            out = model(data)
            _, pred = F.softmax(out, dim=-1).max(1)
            pred = pred.cpu().numpy().tolist()
            pred_list.extend(pred)
    target_names = ["Chat","Email","File Transfer","Streaming","Voip","VPN: Chat","VPN: File Transfer","VPN: Email","VPN: Streaming","VPN: Voip"]
    target_index = [0, 1, 2, 3, 5, 6, 7, 8, 9, 11]
    target_label_map = dict(zip(target_index, target_names))
    predicted_labels = [target_label_map[i] for i in pred_list]
    df = pd.read_csv(csv_filepath)
    df["predicted_labels"] = predicted_labels

    return df

# def getMatrixfrom_pcap(flname, width):
def getMatrixfrom_pcap(pcap_flpath, width):
    fh_list = []
    for pcap_fl in os.listdir(pcap_flpath):
        full_path = os.path.join(pcap_flpath, pcap_fl)
        with open(full_path, "rb") as f:
            content = f.read()
            hexst = binascii.hexlify(content)
            fh = np.array([int(hexst[i:i+2],16) for i in range(0, len(hexst), 2)])  
            if len(fh) < width * width:
                padnum = width * width - len(fh)
                fh = np.pad(fh, (int(padnum/2), int(padnum-int(padnum/2))), "constant", constant_values=(0))
            fh = np.reshape(fh[:width*width],(-1,width))  
            fh = np.uint8(fh)
            fh_list.append(fh)
    return fh_list

def resolve_input(fh_list, flname):
    data_image = array('B')
    width, height = 0, 0
    for fh in fh_list:
        im = Image.fromarray(fh)
        # im.save(os.path.join(os.getcwd(), "pngdir", "pic_{}.png".format(idx)))
    
        pixel = im.load()
        width, height = im.size
        for x in range(0, width):
            for y in range(0, height):
                data_image.append(pixel[x, y])
    hexval = "{0:#0{1}x}".format(len(data_image), 6)
    hexval = "0x" + hexval[2:].zfill(8)
    header = array("B")
    header.extend([0, 0, 8, 1])
    header.append(int("0x" + hexval[2:][0:2], 16))
    header.append(int("0x" + hexval[2:][2:4], 16))
    header.append(int("0x" + hexval[2:][4:6], 16))
    header.append(int("0x" + hexval[2:][6:8], 16))
    if max([width, height]) <= 256:
        header.extend([0, 0, 0, width, 0, 0, 0, height])
    header[3] = 3
    data_image = header + data_image
    with open(flname, "wb") as outputfile:
        data_image.tofile(outputfile)
    if os.path.exists("{}.gz".format(flname)):
        os.remove("{}.gz".format(flname))
    os.system("gzip {}".format(flname))


if __name__ == "__main__":
    model_path = "./app/model/save_model/checkpoint_model_best.pth"
    pcap_file = "/root/pcap_analysis/store/pcap/vdnwhx9qlp.pcap"
    print(predict_vpn(model_path, pcap_file))
