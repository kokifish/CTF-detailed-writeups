#!/usr/bin/env python3.9
# -*- coding: utf-8 -*-
import string
import random
import socketserver
import signal
import codecs
from os import urandom
from hashlib import sha256
from Crypto.Cipher import AES
from flag import FLAG

BANNER = rb"""

   ___           _    ______                           _   
  |_  |         | |   |  _  \                         | |  
    | |_   _ ___| |_  | | | |___  ___ _ __ _   _ _ __ | |_ 
    | | | | / __| __| | | | / _ \/ __| '__| | | | '_ \| __|
/\__/ / |_| \__ \ |_  | |/ /  __/ (__| |  | |_| | |_) | |_ 
\____/ \__,_|___/\__| |___/ \___|\___|_|   \__, | .__/ \__|
                                            __/ | |        
                                           |___/|_|        
"""

BLOCK_SIZE = 16


class AES_CFB(object):
    def __init__(self):
        self.key = urandom(BLOCK_SIZE)
        self.iv = urandom(16)
        self.aes_encrypt = AES.new(self.key, AES.MODE_CFB, self.iv)
        self.aes_decrypt = AES.new(self.key, AES.MODE_CFB, self.iv)

    def encrypt(self, plain):
        return self.aes_encrypt.encrypt(self.pad(plain))

    def decrypt(self, cipher):
        return self.unpad(self.aes_decrypt.decrypt(cipher))

    @staticmethod
    def pad(s):
        num = BLOCK_SIZE - (len(s) % BLOCK_SIZE)
        return s + bytes([num] * num)

    @staticmethod
    def unpad(s):
        return s[:-s[-1]]


class Task(socketserver.BaseRequestHandler):
    def _recvall(self):
        BUFF_SIZE = 1024
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

    def recv(self, prompt=b'> '):
        self.send(prompt, newline=False)
        return self._recvall()

    def proof_of_work(self):
        random.seed(urandom(32))
        alphabet = string.ascii_letters + string.digits
        proof = ''.join(random.choices(alphabet, k=32))
        hash_value = sha256(proof.encode()).hexdigest()
        self.send(f'sha256(XXXX+{proof[4:]}) == {hash_value}'.encode())
        nonce = self.recv(prompt=b'Give me XXXX > ')
        if len(nonce) != 4 or sha256(nonce + proof[4:].encode()).hexdigest() != hash_value:
            return False
        return True

    def timeout_handler(self, signum, frame):
        raise TimeoutError

    def handle(self):
        try:
            signal.signal(signal.SIGALRM, self.timeout_handler)
            signal.alarm(60)

            self.send(BANNER)

            if not self.proof_of_work():
                self.send(b'\nWrong!')
                self.request.close()
                return

            self.send(b"It's just a decryption system. And I heard that only the Bytedancer can get secret.")

            aes = AES_CFB()

            signal.alarm(300)

            for i in range(52):
                cipher_hex = self.recv(prompt=b'Please enter your cipher in hex > ')
                if len(cipher_hex) > 2048:
                    self.send(b"It's too long!")
                    continue
                try:
                    cipher = codecs.decode(cipher_hex, 'hex')
                except:
                    self.send(b'Not hex data!')
                    continue

                if len(cipher) == 0 or len(cipher) % BLOCK_SIZE != 0:
                    self.send(f'Cipher length must be a multiple of {BLOCK_SIZE}!'.encode())
                    continue

                plaintext = aes.decrypt(cipher)
                plaintext_hex = codecs.encode(plaintext, 'hex')
                self.send(b'Your plaintext in hex: \n%s\n' % plaintext_hex)

                if plaintext == b"Hello, I'm a Bytedancer. Please give me the flag!":
                    self.send(b'OK! Here is your flag: ')
                    self.send(FLAG.encode())
                    break

            self.send(b'Bye!\n')

        except TimeoutError:
            self.send(b'\nTimeout!')
        except Exception as err:
            self.send(b'Something Wrong!')
        finally:
            self.request.close()


class ForkedServer(socketserver.ForkingMixIn, socketserver.TCPServer):
    pass


if __name__ == "__main__":
    HOST, PORT = '0.0.0.0', 30000
    print(HOST, PORT)
    server = ForkedServer((HOST, PORT), Task)
    server.allow_reuse_address = True
    server.serve_forever()
