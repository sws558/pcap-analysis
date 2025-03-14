# coding:UTF-8


import subprocess
import sys
import os
import random

# 上传后缀名校验


def allowed_file(filename):
    ALLOWED_EXTENSIONS = set(['pcap', 'cap', 'pcapng'])
    return '.' in filename and filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS

# 获取文件后缀


def get_filetype(filename):
    return '.' + filename.rsplit('.', 1)[1]

# 生成随机的字符串文件名


def random_name():
    return ''.join(random.sample('1234567890qazxswedcvfrtgbnhyujmkiolp', 10))


def pcapng_to_pcap(pcapng_file):
    '''Converts a pcapng file to pcap for parsing. MUST have tshark installed.'''
    if not os.path.isfile(pcapng_file):
        print("{} is not a file".format(pcapng_file))
        return
    if os.path.splitext(pcapng_file)[1].strip() != ".pcapng":
        print("{} is not a pcapng file".format(pcapng_file))
        return
    command = ['tshark', '-F', 'pcap', '-r',
               pcapng_file, '-w', os.path.splitext(pcapng_file)[0] + '.pcap']
    subprocess.run(command, check=True)
