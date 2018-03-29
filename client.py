# client 
# -*- coding:utf-8 -*-  
  
import socket  
from Crypto.Cipher import AES
from binascii import b2a_hex, a2b_hex
import sys
import hashlib
  
shared_key = "Xi8_hzSvDsl9kdX00gxX62J9s_lwvxz!"
remoteIP = "127.0.0.1"
remotePort = 34851

class prpcrypt():
    def __init__(self,key):
        self.key = key
        self.mode = AES.MODE_CFB
     
    def encrypt(self,text):
        cryptor = AES.new(self.key,self.mode,b'0000000000000000')
        length = 16
        count = len(text)
        if count < length:
            add = (length-count)
            #\0 backspace
            text = text + ('\0' * add)
        elif count > length:
            add = (length-(count % length))
            text = text + ('\0' * add)
        self.ciphertext = cryptor.encrypt(text)
        return b2a_hex(self.ciphertext)
     
    def decrypt(self,text):
        cryptor = AES.new(self.key,self.mode,b'0000000000000000')
        plain_text  = cryptor.decrypt(a2b_hex(text))
        return plain_text.rstrip('\0')
try:
    remoteIP = sys.argv[1]
    remotePort = int(sys.argv[2])
except IndexError:
    print("No remote IP/remote Port specified. Trying localhost@34851")
    print("Usage: client.py [Remote IP] [Remote Port]")
print("Local IP:" + socket.gethostbyname(socket.gethostname()))
print("Remote IP:" + remoteIP)
print("Remote Port:" + str(remotePort))
address = (remoteIP, remotePort)  
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  
try:
    s.connect(address)  
except socket.error:
    print("Host not open.")
    #print("*Protocol: ")
    exit(1)
  
#data = s.recv(512)  
#print 'the data received is',data  
  
s.send('REQ-CNT')  
data = s.recv(512)
processed_data = data.split("=")
if processed_data[0] == "S_FP":
    print("Server sended fingerprint.")
    print("Processing key exchange.")

    enc = prpcrypt(shared_key)

    msg = enc.encrypt(processed_data[1])
    s.send("KEY=" + msg)
    print("Server fingerprint is:" + processed_data[1])
    print("Warning! The server fingerprint is the only way to id the server.")
    print("If you don't trust the server, hit Ctrl-C right now.")
    #print("Normal fingerprint format would be:")
    #print("[IP]:[PORT]-[Bunch of random numbers]   (Not hashed)")
    if raw_input("Connect? [y/n]:") == "y":
        pass
    else:
        print("Connection closed by client.")
        s.close()
        exit(0)
    s.send("CNT+ESB")
    connection_stat = s.recv(512)
    if connection_stat == "CNT+OK":
        print("Auth success, connection established.")
    elif connection_stat == "RST+END":
        print("Auth failed, ending connection now.")
        exit(1)
    while True:
        text_input = raw_input(">")
        if text_input == "CLIENT+quit":
            print("Client side quitting.")
            s.send("0+0")
            exit(0)
        try:
            s.send(str(hashlib.sha512(text_input).hexdigest()) + "+" + enc.encrypt(text_input))
        except socket.error:
            print("Broken pipe. Server suddenly close connection.")
            exit(1)
else:
    print("No key exchange command. Ending the connection.")
    exit(0)
#print(data)
  
s.close()