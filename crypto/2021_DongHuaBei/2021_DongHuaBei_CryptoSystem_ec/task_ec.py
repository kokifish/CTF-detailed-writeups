from Crypto.Util.number import*
import random
# from secret import flag
flag = b'flag{1234567890}'
from hashlib import sha256
import socketserver
import signal
import string

def trans_flag(flag):
    new_flag = []
    for i in range(6):
        new_flag.append(bytes_to_long(flag[i*7:i*7+7]))
    return new_flag

kbits = 1024
table = string.ascii_letters+string.digits
flag = trans_flag(flag)

def Setup(kbits):
    p_bit = kbits//2
    q_bit = kbits - p_bit
    while 1:
        p = getPrime(p_bit)
        p_tmp = (p-1)//2
        if isPrime(p_tmp):
            break
    while 1:
        q = getPrime(q_bit)
        q_tmp = (q-1)//2
        if isPrime(q_tmp):
            break
    N = p*q
    while 1:
        g = random.randrange(N*N)
        if (pow(g,p_tmp * q_tmp,N*N) - 1)%N == 0 and  (pow(g,p_tmp * q_tmp,N*N) - 1)//N >= 1 and (pow(g,p_tmp * q_tmp,N*N) - 1)//N <= N - 1:
            break
    public = (N,g)
    return public,p

def KeyGen(public):
    N,g = public
    a = random.randrange(N*N)
    h = pow(g,a,N*N)

    pk = h
    sk = a 

    return pk,sk

def Encrypt(public,pk,m):
    N,g = public
    r = random.randrange(N*N)
    A = pow(g,r,N*N)
    B = (pow(pk,r,N*N) * (1 + m * N)) % (N * N)
    return A,B

def Add(public,dataCipher1,dataCipher2):
    N = public[0]
    A1,B1 = dataCipher1
    A2,B2 = dataCipher2

    A = (A1*A2)%(N*N)
    B = (B1*B2)%(N*N)

    return (A,B)

def hint(p):
    _p = getPrime(2048)
    _q = getPrime(2048)
    n = _p*_q
    e = 0x10001
    s = getPrime(300)
    tmp = (160 * s ** 5 - 4999 * s ** 4 + 3 * s ** 3 +1)

    phi = (_p-1)*(_q-1)
    d = inverse(e,phi)
    k = (_p-s)*d
    enc = pow(p,e,n)
    return (tmp,k,enc,n)

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

    def recv(self, prompt=b'SERVER <INPUT>: '):
        self.send(prompt, newline=False)
        return self._recvall()

    def proof_of_work(self):
        proof = (''.join([random.choice(table)for _ in range(20)])).encode()
        sha = sha256(proof).hexdigest().encode()
        self.send(b"[+] sha256(XXXX+" + proof[4:] + b") == " + sha )
        XXXX = self.recv(prompt = b'[+] Plz Tell Me XXXX :')
        if len(XXXX) != 4 or sha256(XXXX + proof[4:]).hexdigest().encode() != sha:
            return False
        return True

    def handle(self):
        proof = self.proof_of_work()
        if not proof:
            print('fail')
            self.request.close()

        print(0)
        public,p = Setup(kbits)
        signal.alarm(60)
        pk = []
        print(1)

        for i in range(6):
            pki,ski = KeyGen(public)
            pk.append(pki)
        print(2)

        msg = [123,456,789,123,456,789]
        CipherPair = []
        for i in range(len(pk)):
            TMP = Encrypt(public,pk[i],msg[i])
            CipherPair.append(((TMP),pk[i]))
        print(3)

        CipherDate = []
        for i in range(len(pk)):
            CipherDate.append(Add(public,Encrypt(public,pk[i],flag[i]),CipherPair[i][0]))
        print(4)

        self.send(b'What do you want to get?\n[1]pk_list\n[2]public_parameters\n[3]hint_for_p\n[4]EncRypt_Flag\n[5]exit')
        while 1:
            option = self.recv()
            if option == b'1':
                self.send(b"[~]My pk_list is:")
                self.send(str(pk).encode())
            elif option == b'2':
                self.send(b"[~]My public_parameters is")
                self.send(str(public).encode())
            elif option == b'3':
                self.send(b"[~]My hint for p is")
                self.send(str(hint(p)).encode())
            elif option == b'4':
                self.send(b'[~]What you want is the flag!')
                self.send(str(CipherDate).encode())
            else:
                break
        self.request.close()

class ThreadedServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass
#
# class ForkedServer(socketserver.ForkingMixIn, socketserver.TCPServer):
#     pass

if __name__ == "__main__":
    HOST, PORT = '0.0.0.0', 10004
    print("HOST:POST " + HOST+":" + str(PORT))
    # server = ForkedServer((HOST, PORT), Task)
    server = ThreadedServer((HOST, PORT), Task)
    server.allow_reuse_address = True
    server.serve_forever()