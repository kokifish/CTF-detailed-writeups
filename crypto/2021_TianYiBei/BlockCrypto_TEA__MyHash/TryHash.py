import socketserver
import signal,os,random,string
from hashlib import sha256

# from secret import flag
flag = b'flag{13437523487739102940}'
from ctypes import c_uint32 as uint32
from struct import pack, unpack


class Task(socketserver.BaseRequestHandler):
    # def proof_of_work(self):
    #     random.seed(os.urandom(8))
    #     proof = ''.join([random.choice(string.ascii_letters+string.digits) for _ in xrange(20)])
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

    def myhash(self,msg,identification):
        delta=0x9E3779B9
        v0, v1 = map(uint32, unpack('>2I', msg))
        k0, k1, k2, k3 = map(uint32, unpack('>4I', identification))
        sm, delta = uint32(0), uint32(delta)

        for i in range(32):
            sm.value += delta.value
            v0.value += ((v1.value << 4) + k0.value) ^ (v1.value + sm.value) ^ ((v1.value >> 5) + k1.value)
            v1.value += ((v0.value << 4) + k2.value) ^ (v0.value + sm.value) ^ ((v0.value >> 5) + k3.value)

        return pack('>2I', v0.value, v1.value)

    def handle(self):
        # signal.alarm(200)
        # if not self.proof_of_work():
        #     return
        nounce = os.urandom(8)
        self.dosend(b"Welcome to the Auth System.")
        self.dosend(b'If you are admin, I will give you the flag.\n')   
        adminpass = b'Iamthesuperadmin'
        adminhash = self.myhash(nounce,adminpass)
        for i in range(5):
            self.dosend(b'Choice:\n')
            choice = int(self.dorecv(8))
            if choice == 0:
                self.dosend(b'I can hash for you')
                user = self.dorecv(32)   
                if len(user)!=16:
                    self.request.close()
                    return
                if user == adminpass:
                    self.request.close()
                    return
                userhash = self.myhash(nounce,user)
                self.dosend(userhash+b'\n')
            elif choice == 1:
                self.dosend(b'Are you admin?')
                userhash = self.dorecv(48)
                if userhash == adminhash:
                    self.dosend(flag+b'\n')
                    self.request.close()
                    return
                else:
                    self.dosend(b'You are not admin!\n')
                    self.request.close()
                    return
            else:
                pass       
        
        self.request.close()


# class ForkingServer(socketserver.ForkingTCPServer, socketserver.TCPServer):
#     pass
class ThreadedServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass

if __name__ == "__main__":
    HOST, PORT = '127.0.0.1', 10006
    # server = ForkingServer((HOST, PORT), Task)
    server = ThreadedServer((HOST, PORT), Task)
    server.allow_reuse_address = True
    server.serve_forever()

