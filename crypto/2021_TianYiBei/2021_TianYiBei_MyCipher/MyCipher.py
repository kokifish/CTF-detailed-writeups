import socketserver
import signal,os,random,string
from hashlib import sha256

# from secret import flag

flag = b'flag{743217498372969235100473}'
from struct import pack, unpack

class Task(socketserver.BaseRequestHandler):
    # def proof_of_work(self):
    #     random.seed(os.urandom(8))
    #     proof = ''.join([random.choice(string.ascii_letters+string.digits) for _ in range(20)])
    #     digest = sha256(proof).hexdigest()
    #     self.request.send("sha256(XXXX+%s) == %s\n" % (proof[4:],digest))
    #     self.request.send('Give me XXXX:')
    #     x = self.request.recv(10)
    #     x = x.strip()
    #     if len(x) != 4 or sha256(x+proof[4:]).hexdigest() != digest:
    #         return False
    #     return True

    def dorecv(self,sz):
        try:
            return self.request.recv(sz).strip()
        except:
            return 0

    def dosend(self, msg):
        try:
            self.request.sendall(msg)
        except:
            pass

    def g(self,v1,v2,x):
        value = (v1+v2+x)%256
        value = ((value<<3) | (value>>5)) &0xff
        return value

    def f(self,value):
        v1,v2 = unpack('>2B',pack('>H',value))
        v2 = self.g(v1,v2,1)
        v1 = self.g(v1,v2,0)
        value = unpack('>H',pack('>2B',v1,v2))
        return value[0]

    def encrypt_ecb(self,msg,key):
        l = len(msg)
        if l%4 !=0:
            msg = msg+b'\x00'*(4-(l%4))
        cipher = b''
        for i in range(0,len(msg),4):
            cipher += self.encrypt(msg[i:i+4],key)
        return cipher


    def encrypt(self,msg,key):
        subkeys = unpack('>4H',key)
        left,right = unpack('>2H',msg)
        right = right^subkeys[3]
        for i in range(3):
            tmp = left^self.f(subkeys[i]^right) 
            left = right
            right = tmp
        left = right^left
        return pack('>2H', left, right)

    def handle(self):
        # signal.alarm(200)
        # if not self.proof_of_work():
        #     return
        key = os.urandom(8)
        print(key)
        self.dosend(b'Encrypted flag is:')
        self.dosend(self.encrypt_ecb(flag,key)+b'\n')
        self.dosend(b'Here is your chance:')
        data = self.dorecv(160)
        self.dosend(self.encrypt_ecb(data,key))

        self.request.close()


# class ForkingServer(socketserver.ForkingTCPServer, socketserver.TCPServer):
#     pass
class ThreadedServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass


if __name__ == "__main__":
    HOST, PORT = '127.0.0.1', 10005
    # server = ForkingServer((HOST, PORT), Task)
    server = ThreadedServer((HOST, PORT), Task)
    server.allow_reuse_address = True
    server.serve_forever()

