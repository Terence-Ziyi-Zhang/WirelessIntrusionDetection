import os
import sys
import threading

from PyQt5.Qt import QLineEdit
from PyQt5.QtWidgets import QApplication, QWidget, QPushButton, QLabel, QTextEdit

from LiveDetection import inspect_thread
from LiveDetection import live_capture

global content


class App(QWidget):

    def __init__(self):
        super().__init__()
        self.title = "WLAN入侵检测"
        self.left = 10
        self.top = 10
        self.width = 280
        self.height = 200
        self.initUI()

    def initUI(self):
        self.setWindowTitle(self.title)
        self.setGeometry(self.left, self.top, self.width, self.height)

        # 信道
        self.label1 = QLabel(self)
        self.label1.setText("Channel：")
        self.label1.move(48, 20)

        self.channel = QLineEdit(self)
        self.channel.move(110, 20)
        self.channel.resize(50, 20)
        self.channel.setText("9")

        # 时长
        self.label2 = QLabel(self)
        self.label2.setText("Duration(s)：")
        self.label2.move(30, 50)

        self.duration_time = QLineEdit(self)
        self.duration_time.move(110, 50)
        self.duration_time.resize(50, 20)
        self.duration_time.setText("inf")

        # 缓存路径
        self.label3 = QLabel(self)
        self.label3.setText("Storage Path：")
        self.label3.move(18, 80)

        self.buffer_path = QLineEdit(self)
        self.buffer_path.move(110, 80)
        self.buffer_path.resize(150, 20)
        self.buffer_path.setText("/tmp/capture/")

        # 启动按钮
        self.activate = QPushButton('Activate', self)
        self.activate.move(50, 130)
        self.activate.clicked.connect(self.on_click1)

        # 停止按钮
        self.stop = QPushButton('Stop', self)
        self.stop.move(150, 130)
        self.stop.clicked.connect(self.on_click2)

        # 初始化线程
        self.cap_thread = threading.Thread()
        self.ins_thread = threading.Thread()

        os.popen("airport -z")

        self.show()

    def on_click1(self):
        # 获取参数
        channel = self.channel.text()
        duration_time = self.duration_time.text()
        if duration_time == "inf" or duration_time == "":
            duration_time = "99999"
        buffer_path = self.buffer_path.text()

        if self.cap_thread.isAlive() or self.ins_thread.isAlive():
            print("*** Detection in progress! *** ")
        else:
            # Ensure the buffer directory
            if os.path.exists(buffer_path):
                for _, _, file_names in os.walk(buffer_path):
                    for file_name in file_names:
                        os.remove(buffer_path + file_name)
            else:
                os.makedirs(buffer_path)

            # 设置线程
            self.cap_thread = threading.Thread(target=live_capture, args=(channel, duration_time, buffer_path))
            self.ins_thread = threading.Thread(target=inspect_thread, args=(buffer_path,))

            # 开始线程
            self.cap_thread.start()
            self.ins_thread.start()

    def on_click2(self):
        if self.cap_thread.isAlive() or self.ins_thread.isAlive():
            # 杀掉进程
            PIDs = os.popen("ps -e | grep 'tshark' | awk '{print $1}'").read()
            PID = ""
            for i in range(10):
                if i < len(PIDs):
                    if not PIDs[i] == '\n':
                        PID = PID + PIDs[i]
                    else:
                        break
            os.popen("kill -9 " + PID).read()
        else:
            print("*** No Detection is on! ***")

    def closeEvent(self, event):
        if self.cap_thread.isAlive() or self.ins_thread.isAlive():
            # 杀掉进程
            PIDs = os.popen("ps -e | grep 'tshark' | awk '{print $1}'").read()
            PID = ""
            for i in range(10):
                if i < len(PIDs):
                    if not PIDs[i] == '\n':
                        PID = PID + PIDs[i]
                    else:
                        break
            os.popen("kill -9 " + PID)
        os.popen("ifconfig en0 up")


if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = App()
    app.exit(app.exec_())
