from ftplib import FTP
from time import sleep
from scapy.all import *
import threading
phone_addr = '192.168.43.1'
phone_port = 1024
file_path = 'b.txt'
file_sent = False
ftp = FTP()

def connect_to_phone():
    ftp.connect(phone_addr, phone_port)
    ftp.login()

def send_file():
    file = open(file_path, 'rb')  # file to send
    ftp.storbinary('STOR b.txt', file)  # send the file
    file.close()  # close file and FTP
    ftp.quit()

def scapy_sniffer():
    packets = sniff(stop_filter=stop_filter)
    wrpcap('C:\\Users\\Oren Jacobian Pana\\Desktop\\sniffed.pcap', packets)

def stop_filter(x):
    return file_sent == True

def start_sniff_thread():
    th = threading.Thread(target=scapy_sniffer)
    th.start()

if __name__ == "__main__":
    connect_to_phone()
    start_sniff_thread()
    send_file()
    file_sent = True # stop sniffing