from pathlib import Path

import numpy as np
from scapy.compat import raw
from scapy.layers.dns import DNS
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Padding
from scapy.utils import rdpcap
from scipy import sparse


def remove_ether_header(packet):
    if Ether in packet:
        return packet[Ether].payload
    return packet


def mask_ip(packet):
    if IP in packet:
        packet[IP].src = '0.0.0.0'
        packet[IP].dst = '0.0.0.0'

    return packet


def pad_udp(packet):
    if UDP in packet:
        # get layers after udp
        layer_after = packet[UDP].payload.copy()

        # build a padding layer
        pad = Padding()
        pad.load = '\x00' * 12

        layer_before = packet.copy()
        layer_before[UDP].remove_payload()
        packet = layer_before / pad / layer_after

        return packet

    return packet


# 填充最大长度1500
def packet_to_sparse_array(packet, max_length):
    arr = np.frombuffer(raw(packet), dtype=np.uint8)[0: max_length] / 255
    if len(arr) < max_length:
        pad_width = max_length - len(arr)
        arr = np.pad(arr, pad_width=(0, pad_width), constant_values=0)

    arr = sparse.csr_matrix(arr)
    return arr


def transform_packet(packet, max_length):
    if should_omit_packet(packet):
        return None

    packet = remove_ether_header(packet)
    packet = pad_udp(packet)
    packet = mask_ip(packet)

    arr = packet_to_sparse_array(packet, max_length)

    return arr


# for malware tyoe identification
MALWARE_ID = {
    "Youmi": 1,  # Adware
    "Mobidash": 1,
    "Shuanet": 1,
    "koodous": 1,
    "Ewind": 1,
    "Gooligan": 1,
    "Feiwo": 1,
    "Dowgin": 1,
    "Selfmite": 1,
    "Kemoge": 1,
    "jifake": 2,  # SMSMalware
    "plankton": 2,
    "Nandrobox": 2,
    "zsone": 2,
    "fakemart": 2,
    "Biige": 2,
    "mazarbot": 2,
    "smssniffer": 2,
    "Beanbot": 2,
    "fakenotify": 2,
    "fakeinst": 2,
    "AVpass": 3,  # Scareware
    "AVforandroid": 3,
    "FakeAV": 3,
    "FakeApp.AL": 3,
    "FakeTaoBao": 3,
    "Penetho": 3,
    "FakeApp": 3,
    "FakeJobOffer": 3,
    "AndroidSpy.277": 3,
    "VirusShield": 3,
    "AndroidDefender": 3,
    "Koler": 0,  # Ransomware
    "Svpeng": 0,
    "RansomBO": 0,
    "Simplocker": 0,
    "WannaLocker": 0,
    "LockerPin": 0,
    "Jisut": 0,
    "Charger": 0,
    "PornDroid": 0,
    "Pletor": 0
}

ID_TO_TYPE = {
    1: "Youmi",  # Adware
    1: "Mobidash",
    1: "Shuanet",
    1: "koodous",
    1: "Ewind",
    1: "Gooligan",
    1: "Feiwo",
    1: "Dowgin",
    1: "Selfmite",
    1: "Kemoge",
    2: "jifake",  # SMSMalware
    2: "plankton",
    2: "Nandrobox",
    2: "zsone",
    2: "fakemart",
    2: "Biige",
    2: "mazarbot",
    2: "smssniffer",
    2: "Beanbot",
    2: "fakenotify",
    2: "fakeinst",
    3: "AVpass",  # Scareware
    3: "AVforandroid",
    3: "FakeAV",
    3: "FakeApp.AL",
    3: "FakeTaoBao",
    3: "Penetho",
    3: "FakeApp",
    3: "FakeJobOffer",
    3: "AndroidSpy.277",
    3: "VirusShield",
    3: "AndroidDefender",
    0: "Koler",  # Ransomware
    0: "Svpeng",
    0: "RansomBO",
    0: "Simplocker",
    0: "WannaLocker",
    0: "LockerPin",
    0: "Jisut",
    0: "Charger",
    0: "PornDroid",
    0: "Pletor"
}

# for traffic identification
TRAFFIC_IDENTIFICATION_ID = {
    "2015": 0,
    "2016": 0,
    "2017": 0,
    "Youmi": 1,
    "Mobidash": 1,
    "Shuanet": 1,
    "koodous": 1,
    "Ewind": 1,
    "Gooligan": 1,
    "Feiwo": 1,
    "Dowgin": 1,
    "Selfmite": 1,
    "Kemoge": 1,
    "jifake": 1,
    "plankton": 1,
    "Nandrobox": 1,
    "zsone": 1,
    "fakemart": 1,
    "Biige": 1,
    "mazarbot": 1,
    "smssniffer": 1,
    "Beanbot": 1,
    "fakenotify": 1,
    "fakeinst": 1,
    "AVpass": 1,
    "AVforandroid": 1,
    "FakeAV": 1,
    "FakeApp.AL": 1,
    "FakeTaoBao": 1,
    "Penetho": 1,
    "FakeApp": 1,
    "FakeJobOffer": 1,
    "AndroidSpy.277": 1,
    "VirusShield": 1,
    "AndroidDefender": 1,
    "Koler": 1,
    "Svpeng": 1,
    "RansomBO": 1,
    "Simplocker": 1,
    "WannaLocker": 1,
    "LockerPin": 1,
    "Jisut": 1,
    "Charger": 1,
    "PornDroid": 1,
    "Pletor": 1
}

ID_TO_IDENTIDICATION_TYPE = {
    0: 'normal',
    1: 'malicious'
}


SINGLE_IDENTIFICATION_ID = {
    "plankton": 1,
    "Nandrobox": 2,
    "fakenotify": 3,
    "Biige": 4,
    "VirusShield": 5,
    "FakeAV": 6,
    "FakeTaoBao": 7,
    "AndroidSpy.277": 8,
    "WannaLocker": 9,
    "RansomBO": 10,
    "LockerPin": 11,
    "Charger": 12,
    "koodous": 13,
    "Youmi": 14,
    "Kemoge": 15,
    "Ewind": 0
}

SINGLE_IDENTIFICATION_ID_TO_TYPE = {
    1: "plankton",
    2: "Nandrobox",
    3: "fakenotify",
    4: "Biige",
    5: "VirusShield",
    6: "FakeAV",
    7: "FakeTaoBao",
    8: "AndroidSpy.277",
    9: "WannaLocker",
    10: "RansomBO",
    11: "LockerPin",
    12: "Charger",
    13: "koodous",
    14: "Youmi",
    15: "Kemoge",
    16: "Ewind"
}


def read_pcap(path: Path):
    packets = rdpcap(str(path))
    return packets


def should_omit_packet(packet):
    # SYN, ACK or FIN flags set to 1 and no payload
    if TCP in packet and (packet.flags & 0x13):
        # not payload or contains only padding
        try:
            layers = packet[TCP].payload.layers()
            if not layers or (Padding in layers and len(layers) == 1):
                return True

    # DNS segment
            if DNS in packet:
                return True
        except AttributeError:
            return False


if __name__ == "__main__":
    print(ID_TO_TYPE)