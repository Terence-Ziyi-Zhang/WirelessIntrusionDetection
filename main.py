import sys
import os
import time
import threading
from PyQt5.QtWidgets import QApplication, QWidget, QPushButton, QAction, QMessageBox, QLabel
from PyQt5.QtGui import QIcon
from PyQt5.QtCore import Qt
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
        self.duration_time.setText("10")

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

        self.stop = QPushButton('Stop', self)
        self.stop.move(150, 130)
        self.stop.clicked.connect(self.on_click2)

        # 初始化线程
        self.cap_thread = threading.Thread()
        self.ins_thread = threading.Thread()

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
            self.cap_thread = threading.Thread(target=capture_thread, args=(channel, duration_time, buffer_path))
            self.ins_thread = threading.Thread(target=inspect_thread, args=(buffer_path,))

            # 开始线程
            self.cap_thread.start()
            self.ins_thread.start()

    def on_click2(self):
        # 如何彻底杀掉进程？
        if self.cap_thread.isAlive() or self.ins_thread.isAlive():
            if self.cap_thread.isAlive():
                _async_raise(self.cap_thread.ident, SystemExit)
                self.cap_thread = None
                self.cap_thread = threading.Thread()

            if self.ins_thread.isAlive():
                _async_raise(self.ins_thread.ident, SystemExit)
                self.ins_thread = None
                self.ins_thread = threading.Thread()
            print("*** Detection stopped. ***")


# 暂停线程
def _async_raise(tid, exctype):
    """raises the exception, performs cleanup if needed"""
    tid = ctypes.c_long(tid)
    if not inspect.isclass(exctype):
        exctype = type(exctype)
    res = ctypes.pythonapi.PyThreadState_SetAsyncExc(tid, ctypes.py_object(exctype))
    if res == 0:
        raise ValueError("invalid thread id")
    elif res != 1:
        # """if it returns a number greater than one, you're in trouble,
        # and you should call it again with exc=NULL to revert the effect"""
        ctypes.pythonapi.PyThreadState_SetAsyncExc(tid, None)
        raise SystemError("PyThreadState_SetAsyncExc failed")


if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = App()
    app.exit(app.exec_())
