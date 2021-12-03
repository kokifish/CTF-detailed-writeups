import random
# from flag import flag,image,r,key1,key2
# import md5
#
# assert(flag[:5]=='CISCN')
# assert(len(str(r))==3)
# data = ''.join(map(chr,image))
# assert(flag[6:-1] == md5.new(data).hexdigest())
# assert(key1<256)
# assert(key2<256)

key1 = 78
key2 = 169
r = 123

x0 = random.random()
x0 = round(x0,6)

def generate(x):
    return round(r*x*(3-x),6)


def encrypt(pixel,key1,key2,x0,m,n):
    num = int(m*n/8)
    seqs = []
    x = x0
    bins = ''
    tmp = []
    for i in range(num):
        x = generate(x)
        tmp.append(x)
        print(x)
        seqs.append(int(x*22000))
    print(tmp)
    for x in seqs:
        bin_x  = bin(x)[2:]
        if len(bin_x) < 16:
            bin_x = '0'*(16-len(bin_x))+bin_x
        bins += bin_x
    assert(len(pixel) == m*n)
    cipher = [ 0 for i in range(m) for j in range(n)]
    for i in range(m):
        for j in range(n):
            index = n*i+j
            ch = int(bins[2*index:2*index+2],2)
            pix = pixel[index]
            if ch == 0:
                pix = (pix^key1)&0xff
            if ch == 1:
                pix = (~pix^key1)&0xff
            if ch == 2:
                pix = (pix^key2)&0xff
            if ch == 3:
                pix = (~pix^key2)&0xff
            cipher[index] = pix 
    return cipher


# flagimage = image
testimage = []
for i in range(16*16):
    testimage.append(random.randint(0,255))
print(testimage)
print(encrypt(testimage, key1, key2, x0, 16, 16))
# print(encrypt(flagimage, key1, key2, x0, 24, 16))



