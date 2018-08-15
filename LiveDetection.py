# Wireless Signal Intrusion Detection

from scapy.all import *
from Detector import Detector
from Detector import normalize

# Global variables
cnt = 0
seq = 0
detector = Detector()

# Parameters
BUFFER_PATH = "/tmp/capture/"
CHANNEL = 9
DURATION_TIME = 15


# Capture and save as a pacp file
def live_capture(channel, duration_time):
    os.popen("airport -z").read()
    os.popen("airport --channel=%s" % channel).read()
    os.popen("tshark -a duration:%s -b duration:1 -I -i en0 -n -w %scapture.pcap -F pcap" %
             (duration_time, BUFFER_PATH)).read()


def capture_thread():
    live_capture(CHANNEL, DURATION_TIME)  # Require permission


def modify(seq):
    if len(str(seq)) == 1:
        return "0000" + str(seq)
    elif len(str(seq)) == 2:
        return "000" + str(seq)
    elif len(str(seq)) == 3:
        return "00" + str(seq)
    elif len(str(seq)) == 4:
        return "0" + str(seq)
    elif len(str(seq)) == 5:
        return str(seq)


def search():
    global cnt
    global seq
    cnt = 0
    seq = seq + 1
    status = 0
    for _, _, file_names in os.walk(BUFFER_PATH):
        for file_name in file_names:
            if file_name.find(modify(seq)) >= 0:
                print("Sniffing", file_name)
                status = 1
                sniff(offline=BUFFER_PATH + file_name, prn=parse)
                print("Sniffing finished. ")
    if status == 0:
        print("File not found. ")
        seq = seq - 1


# Parsing
def parse(frame):
    global cnt
    global detector
    if frame.haslayer(Dot11):  # 802.11 frame
        cnt = cnt + 1
        if frame.type == 0 and (frame.subtype == 11 or frame.subtype == 12):  # Auth/Deauth frame
            vector = normalize(frame)
            result = detector.detect(vector)
            if result[0][0] > 0.5 and result[0][1] < 0.5 and result[0][2] < 0.5:
                print("802.11 frame no." + str(cnt) + ":", "Authentication attack detected!")
                # print(frame.show())
                print("---------------------------------------------")
            elif result[0][0] < 0.5 and result[0][1] > 0.5 and result[0][2] < 0.5:
                print("802.11 frame no." + str(cnt) + ":", "Deauthentication attack detected!")
                # print(frame.show())
                print("---------------------------------------------")


if __name__ == '__main__':

    if os.path.exists(BUFFER_PATH):
        for _, _, file_names in os.walk(BUFFER_PATH):
            for file_name in file_names:
                os.remove(BUFFER_PATH + file_name)
    else:
        os.makedirs(BUFFER_PATH)

    cap_thread = threading.Thread(target=capture_thread)
    cap_thread.start()

    time.sleep(1)
    print("starting sniffing")
    while 1:
        time.sleep(1)
        search()
