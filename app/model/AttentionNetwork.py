import random

import keras.backend as K
from keras import initializers
from keras.layers import Layer


# 层次网络框架
class HierarchicalAttentionNetwork(Layer):
    def __init__(self, attention_dim):
        self.init = initializers.get('normal')
        self.supports_masking = True
        self.attention_dim = attention_dim
        super(HierarchicalAttentionNetwork, self).__init__()

    def build(self, input_shape):
        assert len(input_shape) == 3
        unique_id = random.randint(1, 99999999)  # quite unlike
        #权重
        self.W = K.variable(self.init((input_shape[-1], self.attention_dim)), name=str(unique_id))
        unique_id2 = random.randint(1, 99999999)  # quite unlike
        #偏置项
        self.b = K.variable(self.init((self.attention_dim,)), name=str(unique_id2))
        unique_id3 = random.randint(1, 99999999)  # quite unlike
        # 注意力机制的权重
        self.u = K.variable(self.init((self.attention_dim, 1)), name=str(unique_id3))
        self._trainable_weights = [self.W, self.b, self.u]
        super(HierarchicalAttentionNetwork, self).build(input_shape)

    def compute_mask(self, inputs, mask=None):
        return mask

    def call(self, x, mask=None):
        # size of x :[batch_size, sel_len, attention_dim]
        # size of u :[batch_size, attention_dim]
        # uit = tanh(xW+b)
        uit = K.tanh(K.bias_add(K.dot(x, self.W), self.b))

        ait = K.exp(K.squeeze(K.dot(uit, self.u), -1))

        if mask is not None:
            # Cast the mask to floatX to avoid float64 upcasting
            ait *= K.cast(mask, K.floatx())
        ait /= K.cast(K.sum(ait, axis=1, keepdims=True) + K.epsilon(), K.floatx())
        weighted_input = x * K.expand_dims(ait)
        output = K.sum(weighted_input, axis=1)

        return output

    def compute_output_shape(self, input_shape):
        return input_shape[0], input_shape[-1]
