from aes import AES
from flag import key,flag
import os,hashlib,random
assert (flag[:5] == 'CISCN')
assert (flag[6:-1]==hashlib.md5(key).hexdigest())
plain = os.urandom(16)
print (AES(key).encrypt_block(plain))
cipher,k = AES(key).encrypt_block_(plain,random.randint(0,255))
print (cipher)
piece1 = [k[0],k[1],k[4],k[7],k[10],k[11],k[13],k[14]]
print (hashlib.md5(bytes(piece1)).hexdigest())
piece2 = [k[2],k[3],k[5],k[6],k[8],k[9],k[12],k[15]]
print (hashlib.md5(bytes(piece2)).hexdigest())


