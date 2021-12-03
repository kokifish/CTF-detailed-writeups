from Crypto.Util.number import*
from Crypto.Cipher import AES
from secret import flag
from my_encrypt import block_encrypt
from hashlib import sha256
import socketserver
import signal
import string
import random
import os

table = string.ascii_letters+string.digits

MENU = br'''[+] 1.Encrypt the Flag:
[+] 2.Encrypt your Plaintext:
[+] 3.Exit:
'''

def pad(m):
    padlen = 16 - len(m) % 16
    return m + padlen * bytes([padlen])

def xor(msg1,msg2):
    assert len(msg1)==len(msg2)
    return long_to_bytes(bytes_to_long(msg1)^bytes_to_long(msg2))

class Task(socketserver.BaseRequestHandler):
    def _recvall(self):
        BUFF_SIZE = 2048
        data = b''
        while True:
            part = self.request.recv(BUFF_SIZE)
            data += part
            if len(part) < BUFF_SIZE:
                break
        return data.strip()

    def send(self, msg, newline=True):
        try:
            if newline:
                msg += b'\n'
            self.request.sendall(msg)
        except:
            pass

    def recv(self, prompt=b'[-] '):
        self.send(prompt, newline=False)
        return self._recvall()

    def proof_of_work(self):
        proof = (''.join([random.choice(table)for _ in range(20)])).encode()
        sha = sha256( proof ).hexdigest().encode()
        self.send(b"[+] sha256(XXXX+" + proof[4:] + b") == " + sha )
        XXXX = self.recv(prompt = b'[+] Plz Tell Me XXXX :')
        if len(XXXX) != 4 or sha256(XXXX + proof[4:]).hexdigest().encode() != sha:
            return False
        return True


    def enc_msg(self,msg):
        return block_encrypt(pad(msg),self.key,self.ivv)

    def handle(self):
        signal.alarm(50)
        if not self.proof_of_work():
            return
        self.ivv = os.urandom(16)
        self.key = os.urandom(16)
        while 1:
            self.send(MENU,newline = False)
            option = self.recv()

            if (option == b'1'):
                self.send(b"My Encrypted flag is:")
                self.send(self.enc_msg(flag))

            elif option == b'2':
                self.send(b"Give me Your Plain & I'll give you the Cipher.")
                plaintext = self.recv()
                self.send(b'PlainText:' + plaintext + b'\nCipherText:' + self.enc_msg(plaintext))
            else:
                break
        self.send(b"\n[.]Down the Connection.")
        self.request.close()

class ThreadedServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass

class ForkedServer(socketserver.ForkingMixIn, socketserver.TCPServer):
    pass

if __name__ == "__main__":
    HOST, PORT = '0.0.0.0', 10004
    print("HOST:POST " + HOST+":" + str(PORT))
    server = ForkedServer((HOST, PORT), Task)
    server.allow_reuse_address = True
    server.serve_forever()