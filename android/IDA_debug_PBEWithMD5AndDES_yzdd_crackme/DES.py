import pyDes
import hashlib
import sys


def PBKDF1(password, salt, c=1200, dkLen=20):
    ''' From PKCS#5 2.0 sect 5.1
    PBKDF1 (P, S, c, dkLen)
    Options: Hash underlying hash function
    Input: P password, an octet string
    S salt, an eight-octet string
    c iteration count, a positive integer
    dkLen intended length in octets of derived key, a positive integer, at most
    16 for MD2 or MD5 and 20 for SHA-1
    Output: DK derived key, a dkLen-octet string    '''

    dkMaxLen = hashlib.md5().digest_size  # md5: dkMaxLen=16
    assert(dkLen <= dkMaxLen)  # derived key too long
    assert(len(salt) == 8)  # Salt should be 8 bytes'

    T = hashlib.md5(password + salt).digest()
    for _ in range(2, c + 1):
        T = hashlib.md5(T).digest()

    return T[:dkLen]  # the derived key DK


def DES(text, key, padding, isEncrypt):
    # Initializing variables required
    isDecrypt = not isEncrypt
    # Generating keys
    keys = generateKeys(key)  # list, composed of 0 1 # len(keys)=16, len(keys[0])=48
    # Splitting text into 8 byte blocks
    plainText8ByteBlocks = nSplit(text, 8)  # list, composed of str with 8B
    result = []

    # For all 8-byte blocks of text
    for block in plainText8ByteBlocks:

        # Convert the block into bit array
        block = stringToBitArray(block)  # before: bytes or str # after: list, Composed of 0 1
        # Do the initial permutation
        block = permutation(block, initialPermutationMatrix)

        # Splitting block into two 4 byte (32 bit) sized blocks
        leftBlock, rightBlock = nSplit(block, 32)

        temp = None

        # Running 16 identical DES Rounds for each block of text
        for i in range(16):
            # Expand rightBlock to match round key size(48-bit)
            expandedRightBlock = expand(rightBlock, expandMatrix)

            # Xor right block with appropriate key
            if isEncrypt == True:
                # For encryption, starting from first key in normal order
                temp = xor(keys[i], expandedRightBlock)
            elif isDecrypt == True:
                # For decryption, starting from last key in reverse order
                temp = xor(keys[15 - i], expandedRightBlock)
            # Sbox substitution Step
            temp = SboxSubstitution(temp)
            # Permutation Step
            temp = permutation(temp, eachRoundPermutationMatrix)
            # XOR Step with leftBlock
            temp = xor(leftBlock, temp)

            # Blocks swapping
            leftBlock = rightBlock
            rightBlock = temp

        # Final permutation then appending result
        result += permutation(rightBlock + leftBlock, finalPermutationMatrix)

    # Converting bit array to string
    finalResult = bitArrayToString(result)

    return finalResult


def generateKeys(key):
    """Function to generate keys for different rounds of DES."""
    # Inititalizing variables required
    keys = []
    key = stringToBitArray(key)

    # Initial permutation on key
    key = permutation(key, keyPermutationMatrix1)

    # Split key in to (leftBlock->LEFT), (rightBlock->RIGHT)
    leftBlock, rightBlock = nSplit(key, 28)

    # 16 rounds of keys
    for i in range(16):
        # Do left shifting (different for different rounds)
        leftBlock, rightBlock = leftShift(leftBlock, rightBlock, SHIFT[i])
        # Merge them
        temp = leftBlock + rightBlock
        # Permutation on shifted key to get next key
        keys.append(permutation(temp, keyPermutationMatrix2))

    # Return generated keys
    return keys


# Matrix used for shifting after each round of keys
SHIFT = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
# Expand matrix to get a 48bits matrix of datas to apply the xor with Ki
expandMatrix = [
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1
]


def expand(array, table):
    """Function to expand the array using table."""
    # Returning expanded result
    return [array[element - 1] for element in table]


SboxesArray = [
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
    ],

    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
    ],

    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
    ],

    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
    ],

    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
    ],

    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
    ],

    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
    ],

    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
    ]
]

# Permutation matrix for key
keyPermutationMatrix1 = [
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4
]

# Permutation matrix for shifted key to get next key
keyPermutationMatrix2 = [
    14, 17, 11, 24, 1, 5, 3, 28,
    15, 6, 21, 10, 23, 19, 12, 4,
    26, 8, 16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55, 30, 40,
    51, 45, 33, 48, 44, 49, 39, 56,
    34, 53, 46, 42, 50, 36, 29, 32
]

# Initial Permutation Matrix for data
initialPermutationMatrix = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
]


# Permutation Matrix used after each SBox substitution for each round
eachRoundPermutationMatrix = [
    16, 7, 20, 21, 29, 12, 28, 17,
    1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9,
    19, 13, 30, 6, 22, 11, 4, 25
]

# Final Permutation Matrix for data after 16 rounds
finalPermutationMatrix = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
]


def SboxSubstitution(bitArray):
    """Function to substitute all the bytes using Sbox."""

    # Split bit array into 6 sized chunks
    # For Sbox indexing
    blocks = nSplit(bitArray, 6)
    result = []

    for i in range(len(blocks)):
        block = blocks[i]
        # Row number to be obtained from first and last bit
        row = int(str(block[0]) + str(block[5]), 2)
        # Getting column number from the 2,3,4,5 position bits
        column = int(''.join([str(x) for x in block[1:-1]]), 2)
        # Taking value from ith Sbox in ith round
        sboxValue = SboxesArray[i][row][column]
        # Convert the sbox value to binary
        binVal = binValue(sboxValue, 4)
        # Appending to result
        result += [int(bit) for bit in binVal]

    # Returning result
    return result


def permutation(array, table):
    """Function to do permutation on the array using table."""
    # Returning permuted result
    return [array[element - 1] for element in table]


def leftShift(list1, list2, n):
    """Function to left shift the arrays by n."""
    # Left shifting the two arrays
    return list1[n:] + list1[:n], list2[n:] + list2[:n]


def nSplit(list, n):
    """Function to split a list into chunks of size n."""
    # Chunking and returning the array of chunks of size n
    # and last remainder
    return [list[i: i + n] for i in range(0, len(list), n)]


def xor(list1, list2):
    """Function to return the XOR of two lists."""
    # Returning the xor of the two lists
    return [element1 ^ element2 for element1, element2 in zip(list1, list2)]


def binValue(val, bitSize):
    """Function to return the binary value as a string of given size."""

    binVal = bin(val)[2:] if isinstance(val, int) else bin(ord(val))[2:]

    # Appending with required number of zeros in front
    while len(binVal) < bitSize:
        binVal = "0" + binVal

    # Returning binary value
    return binVal


def stringToBitArray(text):
    """Funtion to convert a string into a list of bits."""

    # Initializing variable required
    bitArray = []
    for letter in text:
        # Getting binary (8-bit) value of letter
        binVal = binValue(letter, 8)
        # Making list of the bits
        binValArr = [int(x) for x in list(binVal)]
        # Apending the bits to array
        bitArray += binValArr

    # Returning answer
    return bitArray


def bitArrayToString(array):
    """Function to convert a list of bits to string."""

    # Chunking array of bits to 8 sized bytes
    byteChunks = nSplit(array, 8)
    # Initializing variables required
    stringBytesList = []
    stringResult = ''
    # For each byte
    for byte in byteChunks:
        bitsList = []
        for bit in byte:
            bitsList += str(bit)
        # Appending byte in string form to stringBytesList
        stringBytesList.append(''.join(bitsList))

    # Converting each stringByte to char (base 2 int conversion first)
    # and then concatenating
    result = ''.join([chr(int(stringByte, 2)) for stringByte in stringBytesList])

    # Returning result
    return result


def DEScrackmeNoPadding(IV, PlainText, key=b"\xe7\x98\x07\x95\xf3\x8eb\xf7", isEncrypt=True):
    IV = b"\x08\x08\x08\x08\x08\x08\x08\x08"
    # print("[PlainText]", type(PlainText), len(PlainText), PlainText)
    PlainText = bytes.fromhex(PlainText)
    # print("[PlainText]", type(PlainText), len(PlainText), PlainText)
    PlainTextXor = bitArrayToString(xor(stringToBitArray(IV), stringToBitArray(PlainText)))
    # print("[PlainTextXor]", type(PlainTextXor), len(PlainTextXor), PlainTextXor, str2hexstr(PlainTextXor))
    out = DES(PlainTextXor, key, "", isEncrypt=True)
    return out


def str2hexstr(s):
    # str to hex representation str
    r = ''.join(["%02X" % ord(x) for x in s])  # .strip()
    return r.upper()


def str2bytes(s):
    # for ascii only
    s = str2hexstr(s)
    return bytes.fromhex(s)


def test():
    plain = b"flag{A!k00000000"
    IV = [27, -60, 103, -69, 9, -128, -26, -26]
    IVbytearr = bytearray(8)
    for i in range(len(IV)):
        IV[i] = IV[i] & 0xff
        IVbytearr[i] = IV[i]
    # print("[IVbytearr]", IVbytearr, ", len=", len(IVbytearr))

    DerivedKey = PBKDF1(b"Google", b"AndroidN", c=50, dkLen=16)
    # print("[DerivedKey]", DerivedKey, len(DerivedKey), "key:", DerivedKey[0:8], "IV:", DerivedKey[8:])

    out = DES("12345678", "12345678", "", isEncrypt=True)
    # print("[DES]", type(out), out, len(out), str2hexstr(out))  # 96d0028878d58c89 3d7595a98bff809d
    out = DEScrackmeNoPadding(b"\x08\x08\x08\x08\x08\x08\x08\x08", "A8A0787701020304")
    # print("[DES]", type(out), len(out), out, str2hexstr(out))  #
    out = DES(out, b"\xe7\x98\x07\x95\xf3\x8eb\xf7", "", isEncrypt=False)
    out = bitArrayToString(xor(stringToBitArray(out), stringToBitArray(b"\x08\x08\x08\x08\x08\x08\x08\x08")))
    # print("[DES]", type(out), len(out), out, str2hexstr(out))


if __name__ == "__main__":  # arg looks like "A8A0787701020304"
    test()
    assert(len(sys.argv) >= 2)
    plaintext = sys.argv[1]
    assert(len(plaintext) == 16)
    # print("[plaintext]", type(plaintext), len(plaintext), plaintext)
    out = DEScrackmeNoPadding(b"\x08\x08\x08\x08\x08\x08\x08\x08", plaintext)
    print(str2hexstr(out))
