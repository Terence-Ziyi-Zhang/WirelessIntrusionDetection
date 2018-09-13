# Wireless Signal Intrusion Detection

Capturing 802.11 frames while detecting authentication/deauthentication flood attack based on a neural network.

Requirements:
* Python 3.6
* Tensorflow
* Scapy
* PyQt5

Notice:
* It is for macOS only, due to the use of specific shell script and tshark command.
* The program needs to switch your network adapter's mode to MONITOR, so you must run your IDE under root authority.
* Because of MONITOR mode, you will not be accessible to any network while running this program.

To initiate the program, run main.py directly.