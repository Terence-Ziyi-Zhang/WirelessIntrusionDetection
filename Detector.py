# Wireless Signal Intrusion Detection

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


# Neural layer
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


# Neural network model
class Detector(object):

    def __init__(self):
        # Placeholders
        self.data = tf.placeholder(tf.float32, [None, 5], name="feature")
        self.label = tf.placeholder(tf.float32, [None, 3], name="label")
        self.keep_prob = tf.placeholder(tf.float32)
        # Hidden layers
        l1 = nn_layer(self.data, 5, 10, self.keep_prob, activation_function=tf.nn.relu)
        l2 = nn_layer(l1, 10, 10, self.keep_prob, activation_function=tf.nn.relu)
        l3 = nn_layer(l2, 10, 10, self.keep_prob, activation_function=tf.nn.relu)
        # Output layer
        self.output = nn_layer(l3, 10, 3, 1.0, activation_function=tf.nn.softmax)
        # Loss and optimization
        loss = tf.reduce_mean(tf.square(self.label - self.output))
        self.training = tf.train.GradientDescentOptimizer(0.1).minimize(loss)
        # Session
        self.sess = tf.Session()
        # Initialization
        init = tf.global_variables_initializer()
        self.sess.run(init)
        # Saver
        self.saver = tf.train.Saver()

    def train(self):
        print("Training in progress... ")
        # Read pcap files
        sniff(offline="./Auth_1.pcap", prn=parse_auth)
        sniff(offline="./Deauth_1.pcap", prn=parse_deauth)
        # Training
        for i in range(10000):
            self.sess.run(self.training,
                          feed_dict={self.data: [[1, 1, 1, 1, 1]], self.label: [[0, 0, 1]], self.keep_prob: 0.5})
            self.sess.run(self.training,
                          feed_dict={self.data: auth_set[i % 4000], self.label: [[1, 0, 0]], self.keep_prob: 0.5})
            self.sess.run(self.training,
                          feed_dict={self.data: [[1, 1, 1, 0, 1]], self.label: [[0, 0, 1]], self.keep_prob: 0.5})
            self.sess.run(self.training,
                          feed_dict={self.data: deauth_set[i % 6000], self.label: [[0, 1, 0]], self.keep_prob: 0.5})
            self.sess.run(self.training,
                          feed_dict={self.data: [[0, 1, 1, 0, 1]], self.label: [[0, 0, 1]], self.keep_prob: 0.5})
            if i % 100 == 0:
                print(i / 100, "%")
        print("Training finished. ")
        # Save model parameters
        self.saver.save(self.sess, "./WSID2/")  # file_name如果不存在的话，会自动创建

    def detect(self, vector):
        if os.path.exists("./WSID2/"):
            # Restore model parameters
            self.saver.restore(self.sess, "./WSID2/")
            # USE the model
            return self.sess.run(self.output, feed_dict={self.data: vector, self.keep_prob: 1.0})
        else:
            print("Training required. ")


if __name__ == '__main__':
    detector = Detector()
    detector.detect([[0, 1, 1, 1, 0]])
    detector.detect([[0, 0, 0, 0, 1]])
    detector.detect([[1, 1, 1, 1, 1]])
    detector.detect([[1, 1, 1, 0, 1]])
    detector.detect([[0, 1, 1, 0, 1]])
