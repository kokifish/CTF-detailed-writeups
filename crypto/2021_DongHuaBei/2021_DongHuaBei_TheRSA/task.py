from Crypto.Util.number import*
from hashlib import sha256
import socketserver
import signal
import string
import random
from secret import flag

table = string.ascii_letters+string.digits
flag = bytes_to_long(flag)


MENU = br'''[+] 1.Get Encrypt:
[+] 2.Exit:
'''

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

    def EncRy(self):
        p,q = getPrime(512),getPrime(512)
        n = p * q
        phi = (p - 1) * (q - 1)
        e = inverse(self.d, phi)
        c = pow(flag, e, n)
        return(e,n,c)

    def handle(self):
        signal.alarm(60)
        if not self.proof_of_work():
            return
        self.send(b"Welcome to my RSA!")
        self.d = getPrime(random.randint(435, 436))

        while 1:
            self.send(MENU)
            self.send(b"Now!What do you want to do?")
            option = self.recv()
            if option == b'1':
                self.send(str(self.EncRy()).encode())
            else:
                break

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