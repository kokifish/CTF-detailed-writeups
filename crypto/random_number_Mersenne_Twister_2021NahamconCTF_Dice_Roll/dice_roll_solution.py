from gmpy2 import *


def getNum(sss):
    result = sss[sss.find('\n')+1:]
    return result[:result.find('\n')]


from socket import *
import time
host = 'challenge.nahamcon.com'
port = 31217
bufsize = 1024
addr = (host, port)
client = socket(AF_INET, SOCK_STREAM)
client.connect(addr)

msg_mask = client.recv(bufsize)
print msg_mask

# 这个库在https://github.com/kmyk/mersenne-twister-predictor中
from mt19937predictor import MT19937Predictor

predictor = MT19937Predictor()
for _ in range(624):
    print _
    client.send('2'+'\n')
    guess_mask = client.recv(bufsize)
    x = int(getNum(guess_mask))
    predictor.setrandbits(x, 32)

client.send('3\n')
msg = client.recv(bufsize)
client.send(str(predictor.getrandbits(32))+'\n')
guess_mask = client.recv(bufsize)
print guess_mask
