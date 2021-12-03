from hashlib import sha256
import random
from pwn import *
from pwnlib.util.iters import bruteforce
from struct import pack, unpack


def g(v1, v2, x):
    value = (v1 + v2 + x) % 256
    value = ((value << 3) | (value >> 5)) & 0xff
    return value


def f(value):
    v1, v2 = unpack('>2B', pack('>H', value))
    v2 = g(v1, v2, 1)
    v1 = g(v1, v2, 0)
    value = unpack('>H', pack('>2B', v1, v2))
    return value[0]


def decrypt_ecb(cipher, key):
    msg = b''
    print(cipher)
    print(len(cipher))
    for i in range(0, len(cipher), 4):
        msg += decrypt(cipher[i:i + 4], key)
    # print(len(msg))
    return msg.strip(b'\x00')


def decrypt(msg, key):
    subkeys = unpack('>4H', key)
    left, right = unpack('>2H', msg)
    left = right ^ left
    for i in range(3):
        left, right = right, left
        left = left ^ f(subkeys[2 - i] ^ right)
    right = right ^ subkeys[3]
    return pack('>2H', left, right)


def encrypt_ecb(msg, key):
    l = len(msg)
    if l % 4 != 0:
        msg = msg + b'\x00' * (4 - (l % 4))
    cipher = b''
    for i in range(0, len(msg), 4):
        cipher += encrypt(msg[i:i + 4], key)
    return cipher


def encrypt(msg, key):
    subkeys = unpack('>4H', key)
    left, right = unpack('>2H', msg)
    right = right ^ subkeys[3]
    for i in range(3):
        tmp = left ^ f(subkeys[i] ^ right)
        left = right
        right = tmp
    left = right ^ left
    return pack('>2H', left, right)


def dfa_f():
    for i in range(1000):
        input1 = random.randint(0, 0xffff)
        output1 = f(input1)
        input2 = input1 ^ 0x8080
        output2 = f(input2)

        assert (output1 ^ output2 == 0x400)


def genpayload1(num):
    payload = b''
    for i in range(num):
        data1 = random.randint(0, 0xffff)
        data2 = random. randint(0, 0xffff)
        data2diff = data2 ^ 0x8080
        payload += pack('>2H', data1, data2)
        payload += pack('>2H', data1, data2diff)
    return payload


def genpayload2(num):
    payload = b''
    for i in range(num):
        data1 = random.randint(0, 0xffff)
        data2 = random.randint(0, 0xffff)
        data2diff = data2 ^ 0x400
        payload += pack('>2H', data1, data2)
        payload += pack('>2H', data1, data2diff)
    return payload


def testkey_round3(pairs, key):
    for pair in pairs:
        output1 = pair[0]
        output2 = pair[1]
        output1_0, output1_1 = unpack('>2H', output1)
        output2_0, output2_1 = unpack('>2H', output2)
        f_out_diff = output1_1 ^ output2_1 ^ 0x400
        f_in1 = key ^ output1_0 ^ output1_1
        f_in2 = key ^ output2_0 ^ output2_1
        if (f(f_in1) ^ f(f_in2) == f_out_diff):
            # print('!!!!!!!!!', hex(f_out_diff)[2:])
            continue
        else:
            return False
    return True


def testkey_round2(pairs, key, r3key):
    for pair in pairs:
        output1 = pair[0]
        output2 = pair[1]
        output1_0, output1_1 = unpack('>2H', output1)
        output2_0, output2_1 = unpack('>2H', output2)
        output1_r3_1 = output1_0 ^ output1_1
        output2_r3_1 = output2_0 ^ output2_1
        f_out_diff = output1_r3_1 ^ output2_r3_1 ^ 0x400
        f_in1 = key ^ output1_1 ^ f(r3key ^ output1_r3_1)
        f_in2 = key ^ output2_1 ^ f(r3key ^ output2_r3_1)
        if (f(f_in1) ^ f(f_in2) == f_out_diff):
            continue
        else:
            return False
    return True


def attack_round1(msg, cipher, keys):
    ciphers = [cipher[i:i + 4] for i in range(0, len(cipher), 4)]
    msgs = [msg[i:i + 4] for i in range(0, len(msg), 4)]
    c = ciphers[0]
    m = msgs[0]
    output0, output1 = unpack('>2H', c)
    output0 = output0 ^ output1
    input0, input1 = unpack('>2H', m)
    candkeys = []
    for key in keys:
        r2k, r3k = key
        output_r2_1 = output0
        output_r2_0 = output1 ^ f(r3k ^ output0)
        output_r1_1 = output_r2_0
        output_r1_0 = output_r2_1 ^ f(r2k ^ output_r2_0)
        k0 = output_r1_0 ^ input1
        for k in range(0x10000):
            f_in = k ^ output_r1_0
            f_out = output_r1_1 ^ input0
            if f(f_in) == f_out:
                candkeys.append([k, r2k, r3k, k0])
    return candkeys


def attack_round2(msg, cipher, keys):
    ciphers = [cipher[i:i + 4] for i in range(0, len(cipher), 4)]
    cipher_pairs = [(ciphers[i], ciphers[i + 1]) for i in range(0, len(ciphers), 2)]
    candkeys = []
    for r3k in keys:
        for key in range(0x10000):
            if testkey_round2(cipher_pairs, key, r3k):
                candkeys.append([key, r3k])
    return candkeys


def attack_round3(msg, cipher):
    ciphers = [cipher[i:i + 4] for i in range(0, len(cipher), 4)]
    cipher_pairs = [(ciphers[i], ciphers[i + 1]) for i in range(0, len(ciphers), 2)]
    candkeys = []
    for key in range(0x10000):
        if testkey_round3(cipher_pairs, key):
            candkeys.append(key)
    return candkeys


def exploit():
    con = remote('127.0.0.1', 10005)

    # context.log_level = 'debug'
    # con.recvuntil("XXXX+")
    # d = con.recvuntil(")")[:-1]
    # con.recvuntil(" == ")
    # target = con.recvline().strip()
    # ans = bruteforce(lambda x: sha256(x + d).hexdigest() == target, string.letters + string.digits, 4)
    # con.sendlineafter("Give me XXXX", ans)
    # con.recvuntil('is:')
    flag = con.recvline().strip()
    if b'Encrypted' in flag:
        flag = flag[18:]
    print(flag)
    payload = genpayload1(6) + genpayload2(6)
    con.sendlineafter(b':', payload)
    cipher = con.recv(len(payload))
    print(cipher)

    cipher_round3 = cipher[:48]
    msg_round3 = payload[:48]
    possible_keys = attack_round3(msg_round3, cipher_round3)
    print('round3 keys maybe:', possible_keys)
    cipher_round2 = cipher[48:96]
    msg_round2 = payload[48:96]
    possible_keys = attack_round2(msg_round2, cipher_round2, possible_keys)
    print('round2 keys maybe:', possible_keys)
    possible_keys = attack_round1(msg_round2, cipher_round2, possible_keys)
    print('round1&0 keys maybe:', possible_keys)

    for key in possible_keys:
        real_key = pack('>4H', *key)
        print('decrypt with key ', repr(real_key))
        print(repr(decrypt_ecb(flag, real_key)))
    con.close()


# def exploit_local():
#     key = os.urandom(8)
#     print(repr(key))
#     payload = genpayload1(6) + genpayload2(6)
#     cipher = encrypt_ecb(payload, key)
#     cipher_round3 = cipher[:48]
#     msg_round3 = payload[:48]
#     possible_keys = attack_round3(msg_round3, cipher_round3)
#     print('round3 keys maybe:', possible_keys)
#     cipher_round2 = cipher[48:96]
#     msg_round2 = payload[48:96]
#     possible_keys = attack_round2(msg_round2, cipher_round2, possible_keys)
#     print('round2 keys maybe:', possible_keys)
#     possible_keys = attack_round1(msg_round2, cipher_round2, possible_keys)
#     print('round1&0 keys maybe:', possible_keys)
#     flag = 'flag{test}'
#     flag = encrypt_ecb(flag, key)
#     print(decrypt_ecb(flag, key))
#     for key in possible_keys:
#         real_key = pack('>4H', *key)
#         print('decrypt with key ', repr(real_key))
#         print(repr(decrypt_ecb(flag, real_key)))


exploit()