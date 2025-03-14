from xu_net import XuNet
import torch
from PIL import Image
import numpy as np
from torchvision import transforms
import torch.nn as nn
import multiprocessing

# 读取预训练模型--------------------------------------------------------------
# 加载XuNet网络
net = XuNet()

# 0.2 预训练模型
# net.load_state_dict(torch.load("./xu_0.2_hugo_epoch_157_best_acc_val56.95_test69.13.pkl", map_location='cuda:0'))
# net.load_state_dict(torch.load("./xu_0.2_wow_epoch_102_best_acc_val56.25_test66.89.pkl", map_location='cuda:0'))
# net.load_state_dict(torch.load("./xu_0.2_suniward_epoch_117_best_acc_val55.55_test63.99.pkl", map_location='cuda:0'))
# net.load_state_dict(torch.load("./xu_0.2_hill_epoch_114_best_acc_val55.5_test62.2.pkl", map_location='cuda:0'))

# 0.4 预训练模型
# net.load_state_dict(torch.load("./xu/xu_0.4_hugo_epoch_146_best_acc_val64.8_test80.0.pkl", map_location='cuda:0'))
# net.load_state_dict(torch.load("./xu/xu_0.4_wow_epoch_106_best_acc_val64.95_test80.93.pkl", map_location='cuda:0'))
net.load_state_dict(torch.load("./XuNet/xu/xu_0.4_suniward_epoch_159_best_acc_val64.95_test80.17.pkl", map_location='cuda:1'))
# net.load_state_dict(torch.load("./xu/xu_0.4_hill_epoch_146_best_acc_val61.4_test76.55.pkl", map_location='cuda:0'))

# 调用检测模型
net.eval().to('cuda')



# 读取待检测的图像 cover 0 stego 1--------------------------------------------------------------
custom_transform = transforms.Compose([
        transforms.ToTensor()
    ])

stego_sample = Image.open('./XuNet/5001.pgm')
stego_images = np.empty((stego_sample.size[0], stego_sample.size[1], 1), dtype='uint8')
stego_images[:, :, 0] = np.array(stego_sample)
stego_images = custom_transform(stego_images)
stego_images = stego_images.unsqueeze(0).to('cuda')


# 1 1 256 256
output = net(stego_images)
softmax_out = nn.Softmax().to('cuda')

output_softmax = softmax_out(output)
output_softmax = output_softmax.cpu().tolist()
print('The probability of the stego sample:', output_softmax[0][1])

