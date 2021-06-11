from sage.crypto.mq.rijndael_gf import RijndaelGF
import binascii

### p与k都是十六进制的hex字符串，p的长度是32， k的长度是32
def myaes_enc(aes, p, k):
    key_state = aes._hex_to_GF(k)
    roundKeys = aes.expand_key(key_state)
    state = aes._hex_to_GF(p)  # TransForm

    for i in range(len(roundKeys) - 2):
        # AddRoundKeys
        state = aes.add_round_key(state, roundKeys[i])
        # subBytes
        state = aes.sub_bytes(state, algorithm='encrypt')
        # shiftRows
        state = aes.shift_rows(state, algorithm='encrypt')
        # MixColumns
        state = aes.mix_columns(state, algorithm='encrypt')
    ### LastRound
    # AddRoundKeys
    state = aes.add_round_key(state, roundKeys[len(roundKeys) - 2])
    # subBytes
    state = aes.sub_bytes(state, algorithm='encrypt')
    # shiftRows
    state = aes.shift_rows(state, algorithm='encrypt')
    # AddRoundKeys
    output = aes.add_round_key(state, roundKeys[len(roundKeys) - 1])

#     print(aes._GF_to_hex(output))
#     print(aes.encrypt(p, k))
    return aes._GF_to_hex(output)


### p与k都是十六进制的hex字符串，p的长度是32， k的长度是32
def myaes_dec(aes, c, k):
    key_state = aes._hex_to_GF(k)
    roundKeys = aes.expand_key(key_state)
    state = aes._hex_to_GF(c)  # TransForm

    ### LastRound
    # AddRoundKeys
    state = aes.add_round_key(state, roundKeys[len(roundKeys) - 1])
    # shiftRows
    state = aes.shift_rows(state, algorithm='decrypt')
    # subBytes
    state = aes.sub_bytes(state, algorithm='decrypt')
    # AddRoundKeys
    state = aes.add_round_key(state, roundKeys[len(roundKeys) - 2])
    
    for i in reversed(range(len(roundKeys) - 2)):
        # MixColumns
        state = aes.mix_columns(state, algorithm='decrypt')
        # shiftRows
        state = aes.shift_rows(state, algorithm='decrypt')
        # subBytes
        state = aes.sub_bytes(state, algorithm='decrypt')
        # AddRoundKeys
        state = aes.add_round_key(state, roundKeys[i])
        
#     print(aes._GF_to_hex(state))
#     print(aes.decrypt(c, k))
    return aes._GF_to_hex(state)


aes = RijndaelGF(4, 4)
K = '2b7e151628aed2a6abf7158809cf4f3c'
plaintext = '00112233445566778899aabbccddeeff'

myaes_enc(aes, plaintext, K)

iv = '0123456789abcdef'

# CBC_mode
# iv xor palintext
P =  hex(int(binascii.hexlify(iv.encode()), 16) ^^ int(plaintext, 16))[2:]
ciphertext = myaes_enc(aes, P, K)
print(ciphertext)
rec = myaes_dec(aes, ciphertext, K)
recP = hex(int(binascii.hexlify(iv.encode()), 16) ^^ int(rec, 16))[2:]
print(recP)