import tensorflow as tf
from scapy.all import *

auth_set = []
deauth_set = []


def parse_auth(frame):
    global auth_set
    if frame.haslayer(Dot11):
        auth_set.append(normalize(frame))


def parse_deauth(frame):
    global deauth_set
    if frame.haslayer(Dot11):
        deauth_set.append(normalize(frame))


def normalize(frame):
    vector = []
    # FC field
    if frame.FCfield & 0xff != 0:
        vector.append(1)
    else:
        vector.append(0)
    # ID
    if frame.ID != 0:
        vector.append(1)
    else:
        vector.append(0)
    # addr1
    if frame.addr1 != "ff:ff:ff:ff:ff:ff":
        vector.append(1)
    else:
        vector.append(0)
    # addr2&3
    if frame.addr2 != frame.addr3:
        vector.append(1)
    else:
        vector.append(0)
    # SC
    if frame.SC != 0:
        vector.append(1)
    else:
        vector.append(0)
    return [vector]


def nn_layer(input_matrix, preceding_layer_neuron_num, this_layer_neuron_num, keep_prob, activation_function=None):
    weights = tf.Variable(tf.truncated_normal(shape=[preceding_layer_neuron_num, this_layer_neuron_num], stddev=0.5),
                          name="Weight")
    biases = tf.Variable(tf.constant(0.5, shape=[this_layer_neuron_num]), name="Bias")
    y = tf.matmul(input_matrix, weights) + biases
    y = tf.nn.dropout(y, keep_prob)
    if activation_function is None:
        output_matrix = y
    else:
        output_matrix = activation_function(y)
    return output_matrix


class Detector(object):

    def __init__(self):
        # 占位符
        self.data = tf.placeholder(tf.float32, [None, 5], name="feature")
        self.label = tf.placeholder(tf.float32, [None, 3], name="label")
        self.keep_prob = tf.placeholder(tf.float32)
        # 隐含层
        l1 = nn_layer(self.data, 5, 10, self.keep_prob, activation_function=tf.nn.relu)
        l2 = nn_layer(l1, 10, 10, self.keep_prob, activation_function=tf.nn.relu)
        l3 = nn_layer(l2, 10, 10, self.keep_prob, activation_function=tf.nn.relu)
        # 输出层
        self.output = nn_layer(l3, 10, 3, 1.0, activation_function=tf.nn.softmax)
        # 损失与优化
        loss = tf.reduce_mean(tf.square(self.label - self.output))
        self.training = tf.train.GradientDescentOptimizer(0.1).minimize(loss)
        # 建立会话
        self.sess = tf.Session()
        # 初始化变量
        init = tf.global_variables_initializer()
        self.sess.run(init)
        # 建立保存/读取器
        self.saver = tf.train.Saver()

    def training(self):
        print("Training in progress... ")
        # 读取Auth
        sniff(offline="./Auth_1.pcap", prn=parse_auth)
        # 读取Deauth
        sniff(offline="./Deauth_1.pcap", prn=parse_deauth)
        # 训练
        for i in range(10000):
            self.sess.run(self.training,
                          feed_dict={self.data: [[1, 1, 1, 1, 1]], self.label: [[0, 0, 1]], self.keep_prob: 0.5})
            self.sess.run(self.training,
                          feed_dict={self.data: auth_set[i % 4000], self.label: [[1, 0, 0]], self.keep_prob: 0.5})
            self.sess.run(self.training,
                          feed_dict={self.data: deauth_set[i % 6000], self.label: [[0, 1, 0]], self.keep_prob: 0.5})
            if i % 100 == 0:
                print(i / 100, "%")
        print("Training finished. ")
        # 保存
        self.saver.save(self.sess, "./Model/WSID/")  # file_name如果不存在的话，会自动创建

    def detect(self, vector):
        if os.path.exists("./WSID/"):
            # 读取
            self.saver.restore(self.sess, "./WSID/")
            # 使用模型
            return self.sess.run(self.output, feed_dict={self.data: vector, self.keep_prob: 1.0})
        else:
            print("Training required. ")


if __name__ == '__main__':
    detector = Detector()
    detector.detect([[0, 1, 1, 1, 0]])
    detector.detect([[0, 0, 0, 0, 1]])
    detector.detect([[1, 1, 1, 1, 1]])
