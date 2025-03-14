import os
import pathlib
import pickle
import subprocess

import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler

from app import app
from app.model.malware_type_class import ModelWang
from app.model.sigle_malware_class_pred import predict
from app.model.predict import predict_vpn

# pickle_file = str(pathlib.Path(__file__).parent.absolute()) + '/pickles/LogReg_1.pkl'

# Data to be (or not) standardized
# not_standard = ['Label', 'Dst Port', 'Protocol']
# not_standard = ['Label', 'Protocol']


##############################
# #      Extra functions     ##
##############################


###############################


# df: dataframe as loaded from csv
# df_predict: dataframe suitable for prediction (less columns) and preprocessed
# df_info: dataframe with info data like timestamp, IPs...
# model: model as loaded from pickle
# filename: csv filename
# only_info: name of the headers of df_info
#
# fun preproc_dataset: preproc function. Prepare dataframes and standardize them
# fun predict: makes a prediction and returns a complete df merging df_info and df_predict

# models.py : 模型，数据库

from .exts import db
from .models import *

# 模型Model：类
# 必须继承 db.Model User才能从普通的类变成模型
class User(db.Model):
    # 表名
    __tablename__ = 'User'   # 数据迁移就是让模型变成表，ORM就是让类变成模型
    # 定义表字段
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    account = db.Column(db.String(30), unique=True, index=True)
    hashed_password = db.Column(db.String(30))



class ModelNIDSV1:
    '''ML python model'''

    def __init__(self, csv_filepath):
        # Loads pickled model
        LIMIT = app.config["MODE_1_LIMIT"]
        pickle_file = pathlib.Path(app.config["MODEL_PATH"])
        with open(pickle_file, 'rb') as f:
            self.model = pickle.load(f)
        self.not_standard = ['Label']
        # If prob >= LIMIT then it is considered attack
        self._LIMIT = LIMIT
        # Loads CSV
        try:
            self.df = pd.read_csv(csv_filepath, sep=",",
                                  header=0, index_col=None, low_memory=False)
        except Exception as e:
            print(e)
            print("File not found")
            exit(3)

        self.csv_filepath = csv_filepath
        return

    def standardize_one(self, standard):
        # what we dont want to standardize
        not_std = self.df[self.not_standard]
        to_std = self.df[standard]  # what we want to standardize

        std = StandardScaler()

        values = std.fit_transform(to_std.values)

        to_std = pd.DataFrame(values, index=to_std.index,
                              columns=to_std.columns)
        return pd.concat([not_std, to_std], axis=1)

    def preproc_dataset(self):
        # We only want some columns.
        # This is the dataframe used to predict, which will need standardization
        self.df_predict = self.df[self.model.data_header]
        return

    def predict(self):
        try:
            x_set = self.df_predict.loc[:, self.df_predict.columns != 'Label']

            labeler = np.vectorize(
                lambda x: 'Attack' if x >= self._LIMIT else 'Benign')

            prediction = self.model.predict_proba(x_set)[:, 1]
            self.df['Label'] = labeler(prediction)
            self.df['Prob'] = prediction
        except Exception:
            print("Error in prediction: Maybe empty pcap?")
            exit(4)

        return self.df

    def save_df(self):
        self.df.to_csv(self.csv_filepath, index=False)
        # 保存之前直接使用df
        return

    @classmethod
    def pcap_to_csv(cls, filepath):
        """
        处理pcap文件
        :param filepath:
        :return: csv
        """

        out = os.path.basename(filepath).replace('.pcap', '.pcap_Flow.csv')

        csv_out = app.config["CSV_FLODER"]
        abs_csv_out = os.path.abspath(csv_out) + "/"
        cfm_bin = app.config["FLOWMETER_FLODER"]
        abs_cfm_bin = os.path.abspath(cfm_bin)
        abs_cfm_bin = os.path.join(abs_cfm_bin, "bin/")
        abs_cfm_bin += "cfm"

        out = os.path.join(abs_csv_out, out)
        try:
            cmd = f"""{abs_cfm_bin} {filepath} {abs_csv_out}"""
            print(cmd)
            exit_code = os.system(cmd)
            # exit_code = subprocess.run([abs_cfm_bin, filepath, abs_csv_out], shell=True)
            if exit_code == 0:
                return out
            elif exit_code == 1:
                os.remove(out)
                return False
            elif exit_code == 2:
                os.remove(out)
                return False
        except Exception as e:
            print(e)
            return False


class ModelNIDSV2:
    def __init__(self, csv_filepath) -> None:
        print(csv_filepath)
        # De-Serializing Model
        self.model = pickle.load(open(os.path.join(os.path.abspath(
            app.config["MODEL_DIR"]), 'nids_model.pkl'), "rb"))
        try:
            self.df = pd.read_csv(csv_filepath, sep=",",
                                  header=0, index_col=None, low_memory=False)
        except Exception as e:
            print(e)
            print("File not found")
            exit(3)

        self.csv_filepath = csv_filepath

    def save_df(self):
        self.df.to_csv(self.csv_filepath, index=False)
        # 保存之前直接使用df
        return
    # TODO: 完成预测

    def preproc_dataset(self):

        cols = [' Bwd Packet Length Std', ' min_seg_size_forward', ' PSH Flag Count',
                ' Min Packet Length', ' Init_Win_bytes_backward', ' ACK Flag Count',
                'Total Length of Fwd Packets', ' Subflow Fwd Bytes',
                'Init_Win_bytes_forward', ' Bwd Packet Length Min', ' Fwd IAT Std',
                ' Flow IAT Max', ' URG Flag Count', ' Destination Port', ' Flow IAT Mean',
                ' Flow Duration', ' Bwd Packets/s', 'Fwd IAT Total', 'Bwd IAT Total',
                ' act_data_pkt_fwd', ' Down/Up Ratio', ' Idle Min', ' Fwd Packet Length Min',
                ' Bwd IAT Max', ' Fwd Packet Length Mean']

        self.df_predict = self.df[cols]
        return

    def predict(self):
        try:
            pred = self.model.predict(self.df_predict)
            label = pred[0]
            if label == 0:
                self.df['Label'] = 'Benign'
            elif label == 1:
                self.df['Label'] = 'Bot'
            elif label == 2:
                self.df['Label'] = 'DDoS'
            elif label == 3:
                self.df['Label'] = 'Infilteration'
            elif label == 4:
                self.df['Label'] = 'PortScan'
            elif label == 5:
                self.df['Label'] = 'Brute-Force'
            elif label == 6:
                self.df['Label'] = 'Sql-Injection'
            elif label == 7:
                self.df['Label'] = 'XSS'
            else:
                print("Error in prediction")
            self.df.rename(columns={"src_ip": "Src IP"}, inplace=True)
            self.df.rename(columns={"dst_ip": "Dst IP"}, inplace=True)
            self.df.rename(columns={"src_port": "Src Port"}, inplace=True)
            self.df.rename(columns={"protocol": "Protocol"}, inplace=True)
            self.df.rename(columns={"timestamp": "Timestamp"}, inplace=True)
            self.df.rename(
                columns={" Destination Port": "Dst Port"}, inplace=True)
        except Exception:
            print("Error in prediction: Maybe empty pcap?")
            exit(4)
        print(self.df.shape)

        return self.df

    @classmethod
    def pcap_to_csv(cls, input_file):

        out = os.path.basename(input_file).replace('.pcap', '.pcap_Flow.csv')

        csv_out = app.config["CSV_FLODER"]
        abs_csv_out = os.path.abspath(csv_out) + "/"
        # cfm_bin = app.config["FLOWMETER_FLODER"]
        # abs_cfm_bin = os.path.abspath(cfm_bin)
        # abs_cfm_bin = os.path.join(abs_cfm_bin, "bin/")
        # abs_cfm_bin += "/cfm"
        out = os.path.join(abs_csv_out, out)
        print(out, "out")
        p = subprocess.Popen(["cicflowmeter", "-f", input_file, "-c", out])
        p.wait()
        return out


def predict_csv(pcap_filename, mode_version=1):
    print(pcap_filename, mode_version)
    if mode_version == 1:#2分类，是否良性,可修改limit=0.75
        csv_file = ModelNIDSV1.pcap_to_csv(pcap_filename)
        model = ModelNIDSV1(csv_file)
        model.preproc_dataset()
        flow_df = model.predict()
        model.save_df()
        return flow_df
    elif mode_version == 2:#多分类，是否为多种攻击方法，改不了
        csv_file = ModelNIDSV2.pcap_to_csv(pcap_filename)
        model = ModelNIDSV2(csv_file)
        model.preproc_dataset()
        flow_df = model.predict()
        model.save_df()
        return flow_df
    elif mode_version == 3:  #四分类，是否为4种恶意加密流量，可修改，natchsize
        # TODO: 路径配置
        model_path = app.config["APP_MODEL_DIR"]
        # weights_path_temp = "/root/opt/analysis/app/model/save_model/_300_30_30_malware_type.hdf5"
        weights_path_temp = os.path.join(model_path, "_300_30_30_malware_type.hdf5")
        model_HANDLE = ModelWang(weights_path=weights_path_temp, num_classes=4)#修改
        flow_df = model_HANDLE.predict(pcap_filename)
        return flow_df
    elif mode_version == 4:  #二分类任务，#是否为VPN
        # TODO: 路径配置
        model_path = app.config["APP_MODEL_DIR"]
        # weights_path_temp = "/root/opt/analysis/app/model/save_model/_300_30_normal_malware.hdf5"
        weights_path_temp = os.path.join(model_path, "_300_30_normal_malware.hdf5")
        model_HANDLE = ModelWang(weights_path=weights_path_temp, num_classes=2)#修改
        flow_df = model_HANDLE.predict(pcap_filename)
        return flow_df
    
    elif mode_version == 5:  #恶意？？？加密流量识别？？？类别，很多
        model_path = app.config["APP_MODEL_DIR"]
        weights_path_temp = os.path.join(model_path, "_300_30_single_malware.hdf5")
        flow_df = predict(weights_path_temp, pcap_filename)
        return flow_df
    
    elif mode_version == 6:  #加密流量分类，VPN类别,修改batchsize
        model_path = app.config["APP_MODEL_DIR"]
        weights_path_temp = os.path.join(model_path, "checkpoint_model_best.pth")
        flow_df = predict_vpn(weights_path_temp, pcap_filename)
        return flow_df