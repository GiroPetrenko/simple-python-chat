# server  
# -*- coding:utf-8 -*- 
  
import socket  
import hashlib
import time
import datetime

from Crypto.Cipher import AES
from binascii import b2a_hex, a2b_hex
 
shared_key = "Xi8_hzSvDsl9kdX00gxX62J9s_lwvxz!"

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

set_hash = "I am a hash that you should trust"
set_hash_hex = hashlib.sha1(set_hash).hexdigest()

print("Local IP:" + socket.gethostbyname(socket.gethostname()))

address = ('127.0.0.1', 34851)  
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # s = socket.socket()  
try:
    s.bind(address)
except socket.error:
    print("Can not bind to host.")
    exit(1)
s.listen(5)  
  
ss, addr = s.accept()  
print 'Got connected from',addr[0]
  
#ss.send('REQ')  
ra = ss.recv(512)  
if ra == "REQ-CNT":
    print("The connection wants to enter secure connection.")
    print("Setted the hash fingerprint to: " + set_hash_hex)
    ss.send("S_FP=" + set_hash_hex)
    ra = ss.recv(512)
    processed_data = ra.split("=")
    if processed_data[0] == "KEY":
        print("Processing Key exchange")
        dec = prpcrypt(shared_key)
        key = dec.decrypt(processed_data[1])
        if key == set_hash_hex:
            print("Key exchange success.")
            if ss.recv(512) == "CNT+ESB":
                pass
            else:
                print("Looks like the client does not want to connect.")
                exit(0)
            ss.send("CNT+OK")
            while True:
                text = ss.recv(512)
                ts = time.time()
                st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
                prc_txt = text.split("+")
                dec_txt = dec.decrypt(prc_txt[1])
                print("["+st+"]@" + addr[0] + ":" + dec_txt)
                if prc_txt[0] == hashlib.sha512(dec_txt).hexdigest():
                    #print("Hash OK!")
                    pass
                else:
                    print("Hashing failed. Data corrupt or man in the middle?")
                if text == "":
                    print("Client Sended Nothing, which means quit.")
                    exit(1)
                elif dec_txt == "CLIENT+quit":
                    ss.close()
                    s.close()
                    exit(0)
        else:
            print("Client side password error, ending the connection now.")
            ss.send("RST+END")
            ss.close()
            s.close()
        #print(key)
    #print(ra)
  
ss.close()  
s.close()  