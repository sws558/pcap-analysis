import torch
import torch.nn as nn
import torch.nn.functional as F


def get_n_params(model):
    pp=0
    for p in list(model.parameters()):
        nn=1
        for s in list(p.size()):
            nn = nn*s
        pp += nn
    return pp


class MHSA(nn.Module):#多注意力机制
    def __init__(self, n_dims, width=14, height=14, heads=4):  #n_dims 输入特征的通道数，宽度，高度，自注意力机制头数
        super(MHSA, self).__init__()
        self.heads = heads

        self.query = nn.Conv2d(n_dims, n_dims, kernel_size=1)
        self.key = nn.Conv2d(n_dims, n_dims, kernel_size=1)
        self.value = nn.Conv2d(n_dims, n_dims, kernel_size=1)

        self.rel_h = nn.Parameter(torch.randn([1, heads, n_dims // heads, 1, height]), requires_grad=True)
        self.rel_w = nn.Parameter(torch.randn([1, heads, n_dims // heads, width, 1]), requires_grad=True) #按照channel划分多头

        self.softmax = nn.Softmax(dim=-1)

    def forward(self, x):
        n_batch, C, width, height = x.size()
        q = self.query(x).view(n_batch, self.heads, C // self.heads, -1)
        k = self.key(x).view(n_batch, self.heads, C // self.heads, -1)
        v = self.value(x).view(n_batch, self.heads, C // self.heads, -1)

        content_content = torch.matmul(q.permute(0, 1, 3, 2), k) #permute 顺序变换，最后两个位置，将channel放在最后

        content_position = (self.rel_h + self.rel_w).view(1, self.heads, C // self.heads, -1).permute(0, 1, 3, 2)
        content_position = torch.matmul(content_position, q)

        energy = content_content + content_position
        attention = self.softmax(energy)

        out = torch.matmul(v, attention.permute(0, 1, 3, 2))
        out = out.view(n_batch, C, width, height)

        return out


class Bottleneck(nn.Module):
    expansion = 4   #通道扩展倍数
#构建块，神经网络
    def __init__(self, in_planes, planes, stride=1, heads=4, mhsa=False, resolution=None):
        super(Bottleneck, self).__init__()

        self.conv1 = nn.Conv2d(in_planes, planes, kernel_size=1, bias=False)
        self.bn1 = nn.BatchNorm2d(planes)
        if not mhsa:
            self.conv2 = nn.Conv2d(planes, planes, kernel_size=3, padding=1, stride=stride, bias=False)
        else:
            self.conv2 = nn.ModuleList()
            self.conv2.append(MHSA(planes, width=int(resolution[0]), height=int(resolution[1]), heads=heads))
            if stride == 2:
                self.conv2.append(nn.AvgPool2d(2, 2))
            self.conv2 = nn.Sequential(*self.conv2)
        self.bn2 = nn.BatchNorm2d(planes)
        self.conv3 = nn.Conv2d(planes, self.expansion * planes, kernel_size=1, bias=False)
        self.bn3 = nn.BatchNorm2d(self.expansion * planes)

        self.shortcut = nn.Sequential()
        if stride != 1 or in_planes != self.expansion*planes:
            self.shortcut = nn.Sequential(
                nn.Conv2d(in_planes, self.expansion*planes, kernel_size=1, stride=stride),
                nn.BatchNorm2d(self.expansion*planes)
            )

    def forward(self, x):
        out = F.relu(self.bn1(self.conv1(x)))
        out = F.relu(self.bn2(self.conv2(out)))
        out = self.bn3(self.conv3(out))
        out += self.shortcut(x)
        out = F.relu(out)
        return out


# reference
# https://github.com/kuangliu/pytorch-cifar/blob/master/models/resnet.py
class ResNet(nn.Module):
    def __init__(self, block, num_blocks, num_classes=12, resolution=(32, 32), heads=4,input_dim=32,hidden_dim = 36,num_layers=2):
        super(ResNet, self).__init__()
        self.in_planes = 64
        self.resolution = list(resolution)

        self.conv1 = nn.Conv2d(1, 64, kernel_size=7, stride=2, padding=3, bias=False)
        # self.conv1 = nn.Conv2d(3, 64, kernel_size=3, stride=1, padding=1, bias=False)
        if self.conv1.stride[0] == 2:
            self.resolution[0] /= 2
        if self.conv1.stride[1] == 2:
            self.resolution[1] /= 2
        self.bn1 = nn.BatchNorm2d(64)
        self.relu = nn.ReLU(inplace=True)
        self.maxpool = nn.MaxPool2d(kernel_size=3, stride=2, padding=1) # for ImageNet
        if self.maxpool.stride == 2:
            self.resolution[0] /= 2
            self.resolution[1] /= 2

        self.layer1 = self._make_layer(block, 64, num_blocks[0], stride=1)
        self.layer2 = self._make_layer(block, 128, num_blocks[1], stride=2)
        self.layer3 = self._make_layer(block, 256, num_blocks[2], stride=2)
        self.layer4 = self._make_layer(block, 512, num_blocks[3], stride=2, heads=heads, mhsa=True)

        self.avgpool = nn.AdaptiveAvgPool2d((1, 1))
        self.fc = nn.Sequential(
            nn.Dropout(0.1), # All architecture deeper than ResNet-200 dropout_rate: 0.2
            nn.Linear(512 * block.expansion+input_dim*hidden_dim*2, num_classes)
        )
        #bilstm
        self.input_dim=input_dim
        self.hidden_dim=hidden_dim
        self.num_layers=num_layers
        self.bi_num=2  #bilstm = 2 ，lstm = 1
        self.device=torch.device("cpu")
        # 定义LSTM网络的输入特征维度，输出，层数，是否batch_first，dropout比例，是否双向
        self.lstm=nn.LSTM(input_size=input_dim,hidden_size=hidden_dim, \
                        num_layers=num_layers,batch_first=True, \
                        dropout=0.1,bidirectional=True)
        # 定义线性分类层，使用logsoftmax输出

    def _make_layer(self, block, planes, num_blocks, stride=1, heads=4, mhsa=False):
        strides = [stride] + [1]*(num_blocks-1)
        layers = []
        for idx, stride in enumerate(strides):
            layers.append(block(self.in_planes, planes, stride, heads, mhsa, self.resolution))
            if stride == 2:
                self.resolution[0] /= 2
                self.resolution[1] /= 2
            self.in_planes = planes * block.expansion
        return nn.Sequential(*layers)

    def init_hidden(self,batch_size):
        # 定义初始的hidden state
        return (torch.zeros(self.num_layers*self.bi_num,batch_size,self.hidden_dim).to(self.device),
                torch.zeros(self.num_layers*self.bi_num,batch_size,self.hidden_dim).to(self.device))
    
    def forward(self, x):  #前向传播
        out1 = self.relu(self.bn1(self.conv1(x)))
        out1 = self.maxpool(out1) # for ImageNet

        out1 = self.layer1(out1)
        out1 = self.layer2(out1)
        out1 = self.layer3(out1)
        out1 = self.layer4(out1)

        out1 = self.avgpool(out1)
        x1 = x.view(-1,32,32)     #这里需要变换维度
        # print(max(x.batch))
        # bs = x.size()[0]
        hidden1=self.init_hidden(x.size()[0])
        out2,hidden = self.lstm(x1,hidden1) 
        out1 = torch.flatten(out1, 1)
        out2 = torch.flatten(out2,1)
        out = torch.cat((out1, out2), dim=1)
        out = self.fc(out)
        return out


def ResNet50(num_classes=12, resolution=(32, 32), heads=4):
    return ResNet(Bottleneck, [3, 4, 6, 3], num_classes=num_classes, resolution=resolution, heads=heads,input_dim=resolution[0],hidden_dim=36,num_layers=2)
# resolution实时计算当前特征矩阵的长宽

def main():
    x = torch.randn([2, 3, 32, 32])   #维度
    # print(x.shape)
    model = ResNet50(resolution=tuple(x.shape[2:]), heads=4)
    # print(model(x).size())
    print(get_n_params(model))


# if __name__ == '__main__':
#     main()