from Crypto.Util.number import *
from base64 import b64decode
from magic_box import *
from tqdm import tqdm
n1, n2 = 64, 12

passage = b"Dat"
seed2 = ''
ifile = open("MTk4NC0wNC0wMQ==_6d30.enc", "rb")
cipher1 = ifile.read()
for i in range(3):
    num = cipher1[i] ^ passage[i]
    # print(bin(num)[2:].zfill(8))
    seed2 += bin(num)[2:].zfill(8)
print(seed2)

# for mask2 in range(1<<12):
#     lfsr2 = lfsr(int(seed2,2), mask2, n2)
#     plain = b''
#     for i in range(3,16):
#         num = cipher1[i] ^ lfsr2.getrandbit(8)
#         plain += long_to_bytes(num)
#     try:
#         if plain.decode().isprintable():
#             print(plain, mask2)
#     except:
#         continue

mask2 = 2053
lfsr2 = lfsr(int(seed2,2), mask2, n2)
plain = b'Dat'
for i in range(3,len(cipher1)):
    num = cipher1[i] ^ lfsr2.getrandbit(8)
    plain += long_to_bytes(num)
print(plain)
# print(b64decode(b'MTk4NC0xMi0yNQ=='))

ifile = open("MTk4NC0xMi0yNQ==_76ff.enc", "rb")
cipher2 = ifile.read()
cipher = ''
passage = b"Date: " + b64decode(b'MTk4NC0xMi0yNQ==')
for i in range(len(passage)):
    num = cipher2[i] ^ passage[i]
    cipher += bin(num)[2:].zfill(8)
# print(len(cipher))
# print(cipher)
# print(cipher2)

mask1 = 9223372036854775811
seed3 = 3054
num = "00000101111011000101010001011100011010000101000001011010100001000000011111100110101010110001000001010110101011011100111000000110"

lfsr1=lfsr(int(num[:64], 2), mask1, n1)
lfsr2=lfsr(seed3, mask2, n2)
lfsr2.getrandbit(64)
ciphergen = generator(lfsr1, lfsr2, 15193544052573546419)
plaintest = b'Date: 19'
for i in cipher2[8:]:
    num = i ^ ciphergen.getrandbit(8)
    plaintest += long_to_bytes(num)
print(plaintest)