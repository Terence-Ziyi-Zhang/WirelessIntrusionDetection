import sys
import os
import time
import threading
from PyQt5.QtWidgets import QApplication, QWidget, QPushButton, QAction, QMessageBox
from PyQt5.QtGui import QIcon
from PyQt5.QtCore import pyqtSlot
from PyQt5.Qt import QLineEdit
from LiveDetection import capture_thread
from LiveDetection import inspect_thread

import inspect
import ctypes


class App(QWidget):

    def __init__(self):
        super().__init__()
        self.title = "WLAN入侵检测"
        self.left = 10
        self.top = 10
        self.width = 320
        self.height = 200
        self.initUI()

    def initUI(self):
        self.setWindowTitle(self.title)
        self.setGeometry(self.left, self.top, self.width, self.height)

        # 信道
        self.channel = QLineEdit(self)
        self.channel.move(20, 20)
        self.channel.resize(50, 20)
        self.channel.setText("9")

        # 时长
        self.duration_time = QLineEdit(self)
        self.duration_time.move(20, 40)
        self.duration_time.resize(50, 20)
        self.duration_time.setText("10")

        # 缓存路径
        self.buffer_path = QLineEdit(self)
        self.buffer_path.move(20, 60)
        self.buffer_path.resize(150, 20)
        self.buffer_path.setText("/tmp/capture/")

        # 启动按钮
        self.activate = QPushButton('Activate', self)
        self.activate.move(20, 100)
        self.activate.clicked.connect(self.on_click1)

        self.show()

    @pyqtSlot()
    def on_click1(self):
        channel = self.channel.text()
        duration_time = self.duration_time.text()
        buffer_path = self.buffer_path.text()

        # Ensure the buffer directory
        if os.path.exists(buffer_path):
            for _, _, file_names in os.walk(buffer_path):
                for file_name in file_names:
                    os.remove(buffer_path + file_name)
        else:
            os.makedirs(buffer_path)

        # Capture frames in a branch thread
        self.cap_thread = threading.Thread(target=capture_thread, args=(channel, duration_time, buffer_path))
        self.ins_thread = threading.Thread(target=inspect_thread, args=(buffer_path,))
        self.cap_thread.start()
        self.ins_thread.start()


if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = App()
    app.exit(app.exec_())
