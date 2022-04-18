from sage.all import *
from scheme import *
import random, string
from hashlib import sha256
from secret import flag

def parse_vector(s):
    return vector(int(i) for i in s.split())

proof = ''.join([random.choice(string.ascii_letters+string.digits) for _ in range(32)]).encode()
digest = sha256(proof).hexdigest()
print(f'sha256(****{proof[4:].decode()}) == {digest}')
print('Please input **** to continue:')
x = input()
if len(x) != 4 or sha256(x.encode() + proof[4:]).hexdigest() != digest:
    print('Invalid proof of work. Aborted.')
    exit(0)

n = 128
pk = load('pk.sobj')

print('Please sign the following message to authenticate:')
s = ''.join([random.choice(string.ascii_letters+string.digits) for _ in range(32)])
print(s)
t = input()
try:
    v = parse_vector(t)
    assert hash_and_verify(pk, s, v)
    print('Authenticated. Here is your flag:')
    print(flag)
except:
    print('Authentication failed!')