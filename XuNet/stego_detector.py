from XuNet.xu_net import XuNet
import torch
from PIL import Image
import numpy as np
from torchvision import transforms
import torch.nn as nn
# torch.cuda.set_device(1)
# device = torch.device('cuda:1' if torch.cuda.is_available() else 'cpu')

class StegoDetector:
    def __init__(self, model_path):
    # 加载XuNet网络
        self.net = XuNet()
        self.net.load_state_dict(torch.load(model_path, map_location='cpu'))
        self.net.eval().to('cpu')

# 转换函数
        self.custom_transform = transforms.Compose([
    transforms.ToTensor()
    ])

    def detect_stego_probability(self, image_path):
        # 读取待检测的图像
        image = Image.open(image_path)
        image_array = np.empty((image.size[0], image.size[1], 1), dtype='uint8')
        image_array[:, :, 0] = np.array(image)
        image_tensor = self.custom_transform(image_array)
        image_tensor = image_tensor.unsqueeze(0).to('cpu')

        # 运行检测模型
        output = self.net(image_tensor)
        softmax_out = nn.Softmax().to('cpu')
        output_softmax = softmax_out(output)
        output_softmax = output_softmax.cpu().tolist()

         # 返回概率
        return output_softmax[0][1]