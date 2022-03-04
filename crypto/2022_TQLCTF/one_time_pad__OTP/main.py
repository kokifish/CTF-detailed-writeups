import os
import random
import secrets
import string

from secret import flag, secret_1, secret_2, flag_token


# ========================================================================


class InvalidChar(Exception):
    pass


class DangerousToken(Exception):
    pass


valid_char = [ord(x) for x in string.digits +
              string.ascii_letters + string.punctuation]


def check_valid(s: bytes):
    r = list(map(lambda x: x in valid_char, s))
    if False in r:
        raise InvalidChar(r.index(False))


def getrandbits(token: bytes, k: int) -> int:
    random.seed(token)
    return random.getrandbits(k)


def bytes_xor_int(s: bytes, r: int, length: int) -> bytes:
    s = int.from_bytes(s, 'little')
    return (s ^ r).to_bytes(length, 'little')


def __byte_shuffle(s: int) -> int:
    bits = list(bin(s)[2:].zfill(8))
    random.shuffle(bits)
    return int(''.join(bits), 2)


def __byte_shuffle_re(s: int) -> int:
    s = bin(s)[2:].zfill(8)
    idx = list(range(8))
    random.shuffle(idx)
    s = ''.join([s[idx.index(i)] for i in range(8)])
    return int(s, 2)


def bits_shuffle(s: bytes) -> bytes:
    s = bytearray(s)
    for i in range(len(s)):
        s[i] = __byte_shuffle(s[i])
    return bytes(s)


def bits_shuffle_re(s: bytes) -> bytes:
    s = bytearray(s)
    for i in range(len(s)):
        s[i] = __byte_shuffle_re(s[i])
    return bytes(s)


def bytes_shuffle(token: bytes, s: bytes) -> bytes:
    random.seed(token)
    s = bytearray(s)
    random.shuffle(s)
    return bytes(s)


def bytes_shuffle_re(token: bytes, s: bytes) -> bytes:
    random.seed(token)
    idx = list(range(len(s)))
    random.shuffle(idx)
    r = bytearray(len(s))
    for i in range(len(s)):
        r[idx[i]] = s[i]
    return bytes(r)


def encrypt(s: str, token=(None, None)):
    if token[0] is None or token[1] is None:
        token = (secrets.randbits(32).to_bytes(4, 'little'),
                 secrets.randbits(32).to_bytes(4, 'little'))
    s: bytes = s.encode()

    check_valid(s)

    r = getrandbits(token[0]+secret_1, 8*len(s))
    s = bytes_xor_int(s, r, len(s))
    s = bits_shuffle(s)
    s += token[0]

    s = bytes_shuffle(token[1]+secret_2, s)
    s += token[1]
    s = s.hex()

    return s


def decrypt(s: str):
    s: bytes = bytes.fromhex(s)

    s, token_1 = s[:-4], s[-4:]
    s = bytes_shuffle_re(token_1+secret_2, s)

    s, token_0 = s[:-4], s[-4:]
    r = getrandbits(token_0+secret_1, 8*len(s))
    s = bits_shuffle_re(s)
    s = bytes_xor_int(s, r, len(s))

    check_valid(s)

    s = s.decode()
    if (len(s) == len(flag)) + (token_0 == flag_token[0]) + (token_1 == flag_token[1]) >= 2:
        raise DangerousToken
    return s


def encrypt_flag():
    flag_enc = encrypt(flag, flag_token)
    print(f'flag: {flag_enc}')


def rebuild():
    global secret_1, secret_2, flag_token
    secret_1 = os.urandom(64)
    secret_2 = os.urandom(64)
    flag_token = (os.urandom(4), os.urandom(4))


def choose_mode():
    print('Choose function:')
    print('0: encrypt')
    print('1: decrypt')
    print('2: rebuild')
    mode = int(input('> '))
    assert 0 <= mode <= 2
    return mode


if __name__ == '__main__':
    print('Welcome to Nano OTP Box!')
    encrypt_flag()

    while True:
        try:
            mode = choose_mode()
            if mode == 0:
                print('Please input original message.')
                msg = input('> ')
                print('encrypted message:', encrypt(msg))
            elif mode == 1:
                print('Please input encrypted message.')
                msg = input('> ')
                print('original message:', decrypt(msg))
            elif mode == 2:
                rebuild()
                encrypt_flag()
        except InvalidChar as e:
            print('The original message contains invalid characters: pos', e)
        except DangerousToken:
            print('The encrypted message contains dangerous token')
