import os
import pathlib
import uuid
from pathlib import Path

import numpy as np
import pandas as pd

from app.wang_utils import read_pcap, transform_packet
from multiprocessing import Pool


def extract_tls_flow(pcap_filepath, output_csv_dir="./csv"):

    pcap_filename = pcap_filepath.split("/")[-1]

    if (os.path.splitext(pcap_filename)[1] == ".pcap" or os.path.splitext(pcap_filename)[1] == ".pcapng"):
        csv_filepath = output_csv_dir + "/" + str(os.path.splitext(pcap_filename)[0]) + ".csv"
        extract_tls_cmd = "tshark -r " + pcap_filepath + \
            " -T fields -Y ssl -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -E separator=\",\" > " + csv_filepath
        # extract_tls_cmd = "tshark -r " + pcap_filepath + \
        #     " -T fields -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -E separator=\",\" > " + csv_filepath
        # print(extract_tls_cmd)
        os.system(extract_tls_cmd)
    return str(os.path.splitext(pcap_filename)[0]) + ".csv"


def addIndex(csv_filepath):

    data = pd.read_csv(csv_filepath, header=None, names=['1', '2', '3', '4'])
    data.to_csv(csv_filepath, index=False)


def removeRepeat(csv_filepath):

    iplist = []
    srcip = []
    dstip = []
    srcport = []
    dstport = []
    alllist = []
    tls = pd.read_csv(csv_filepath)
    for index, row in tls.iterrows():
        s1 = set()
        s1.add(row['1'])
        s1.add(row['2'])
        s1.add(row['3'])
        s1.add(row['4'])
        if (iplist.count(s1)):
            continue
        else:
            iplist.append(s1)
            srcip.append(row['1'])
            dstip.append(row['2'])
            srcport.append(row['3'])
            dstport.append(row['4'])
    alllist.append(srcip)
    alllist.append(dstip)
    alllist.append(srcport)
    alllist.append(dstport)
    df = pd.DataFrame(list(zip(*alllist)), columns=['1', '2', '3', '4'])
    df.to_csv(csv_filepath, index=0)

# 从PCAP中提取单个会话 输出到result文件夹中

def extract_trace(csv_filepath, pcap_filepath, temp_pcap_dir):
    # baseNumber = 0
    tls = pd.read_csv(csv_filepath)
    # print("csv_filepath:", csv_filepath)
    tls['3'].astype('int64')
    tls['4'].astype('int64')
    pcap_basename = os.path.basename(pcap_filepath)
    temp_dir = os.path.join(temp_pcap_dir, pcap_basename)
    os.makedirs(temp_dir)
    cmd_list = []
    for index, row in tls.iterrows():
        # outPath = temp_pcap_dir + pcap_basename + str(baseNumber) + ".pcap"
        # print("index:", index)
        src = row['1']
        dst = row['2']
        srcport = row['3']
        dstport = row['4']
        base_flowname = f"""{src}_{srcport}_{dst}_{dstport}"""
        # print("base_flowname", base_flowname)
        outPath = os.path.join(temp_dir, str(base_flowname) + ".pcap")

        cmdstr = "tshark -r " + str(pcap_filepath) + " -Y \"(ip.src==" + str(src) + " and ip.dst==" + str(dst) \
            + " and tcp.srcport == " + str(srcport) + " and tcp.dstport == " + str(
            dstport) + ") or (ip.src==" + str(dst) + " and ip.dst==" + str(src) + " and tcp.srcport == " \
            + str(dstport) + " and tcp.dstport == " + str(srcport) + ")\" -w " + outPath
        cmd_list.append(cmdstr)
    with Pool(processes=16) as pool:
        pool.map(os.system, cmd_list)
        # os.system(cmdstr)

        # baseNumber = baseNumber + 1


def pcap_to_numpy(main_pcap_dir, numpy_data_dir):
    base_dir = main_pcap_dir.split("/")[-1]
    # 保存每个session中的前N个数据包的前M个字节
    num_packet = 50
    max_bytes = 400
    # output_batch_size = 100

    np_data = []
    for idx, file in enumerate(os.listdir(main_pcap_dir)):

        # 返回当前生成的随机路径
        pcap_filepath = os.path.join(main_pcap_dir, file)
        now = 0
        base_pcap_name = os.path.basename(pcap_filepath).split(".")[0]
        temp_data = np.zeros((num_packet, max_bytes))  # 初始化每个temp中的data
        temp_arr = dict()  # 初始化每个arr，每个数组中的数据都是一个temp

        for j, packet in enumerate(read_pcap(pcap_filepath)):
            temp = transform_packet(packet, max_bytes)
            if temp is not None:
                # 将csr_matrix转化为一位数组
                temp = temp.todense().tolist()[0]
                temp_data[now] = temp  # 保存每个流中的值
                now = now + 1

            if now == num_packet:
                break

        temp_arr["label"] = base_pcap_name
        temp_arr["data"] = temp_data
        # 結果
        np_data.append(temp_arr)


    outTestPath = os.path.join(numpy_data_dir, base_dir)
    # 判断结果
    if not os.path.exists(outTestPath):
        os.makedirs(outTestPath)

    train_part_output_path = Path(str(outTestPath) + "/test_data.npz")
    np.savez(train_part_output_path, data=np.array(np_data))
    return np_data


def preprocess_pcap(pcap_filepath, major_temp_dir="/tmp/pcap_analysis/"):
    # print("preprocess_pcap", "create temp dir")
    major_temp_dir = major_temp_dir + str(uuid.uuid4())
    tls_flow_csv_dir = os.path.join(major_temp_dir, "tls_flow_csv_temp/")
    splited_pcap_dir = os.path.join(major_temp_dir, "split_pcap_temp/")
    numpy_data_dir = os.path.join(major_temp_dir, "numpy_temp/")
    dir_list = [tls_flow_csv_dir, splited_pcap_dir, numpy_data_dir]

    for dir in dir_list:
        pathlib.Path(dir).mkdir(parents=True, exist_ok=True)
    # print("preprocess_pcap", "extract_tls_flow")
    csv_filename = extract_tls_flow(pcap_filepath, tls_flow_csv_dir)

    csv_filepath = os.path.join(tls_flow_csv_dir, csv_filename)

    # pcap_filepath = os.path.join(major_temp_dir, pcap_filepath)
    pcap_filename = os.path.basename(pcap_filepath)
    # print("preprocess_pcap", "addIndex")
    addIndex(csv_filepath)
    # print("preprocess_pcap", "removeRepeat")
    removeRepeat(csv_filepath)
    # print("preprocess_pcap", "extract_trace")
    extract_trace(csv_filepath, pcap_filepath, splited_pcap_dir)
    np_data = pcap_to_numpy(splited_pcap_dir + "/" + pcap_filename, numpy_data_dir)
    return np_data, csv_filepath

def pp_pcap(pcap_filepath, major_temp_dir="/tmp/pcap_analysis/"):
    major_temp_dir = major_temp_dir + str(uuid.uuid4())
    tls_flow_csv_dir = os.path.join(major_temp_dir, "tls_flow_csv_temp/")
    splited_pcap_dir = os.path.join(major_temp_dir, "split_pcap_temp/")
    numpy_data_dir = os.path.join(major_temp_dir, "numpy_temp/")
    dir_list = [tls_flow_csv_dir, splited_pcap_dir, numpy_data_dir]

    for dir in dir_list:
        pathlib.Path(dir).mkdir(parents=True, exist_ok=True)
    # print("preprocess_pcap", "extract_tls_flow")
    csv_filename = extract_tls_flow(pcap_filepath, tls_flow_csv_dir)

    csv_filepath = os.path.join(tls_flow_csv_dir, csv_filename)

    # pcap_filepath = os.path.join(major_temp_dir, pcap_filepath)
    pcap_filename = os.path.basename(pcap_filepath)
    # print("preprocess_pcap", "addIndex")
    addIndex(csv_filepath)
    # print("preprocess_pcap", "removeRepeat")
    removeRepeat(csv_filepath)
    # print("preprocess_pcap", "extract_trace")
    extract_trace(csv_filepath, pcap_filepath, splited_pcap_dir)
    return csv_filepath, splited_pcap_dir+"/"+pcap_filename


if __name__ == "__main__":
    # preprocess_pcap("/home/lzs/lzs/work/analysis/data/Adware/pcaps/pkt2flow.out/tcp_syn/10.42.0.211_60996_76.13.28.196_443_1497502790.pcap")
    preprocess_pcap("/share/hl/pcap_analysis/store/pcap/zv2kt91pua.pcap")
