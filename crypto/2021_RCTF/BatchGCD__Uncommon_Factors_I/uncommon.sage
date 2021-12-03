from multiprocessing import Pool

size = 2^22

flag = open("flag.txt", "rb").read()
assert len(flag) == 22
assert flag[:5] == b"flag{"
assert flag[-1:] == b"}"
seed = flag[5:-1] # 128 bit
seed = (int.from_bytes(seed,'big')<<48) + (randint(0,2^24)<<(128+48)) # 200 bit
ub = seed + 2^48
lb = seed

threads = 64

def f(i):
    p = random_prime(ub, lbound=lb, proof=False)
    q = random_prime(2**312, proof=False)
    N = p*q
    return N

def reseed(i):
    set_random_seed()

pool = Pool(processes=threads)
pool.map(reseed,range(size))
lN = pool.map(f,range(size))
pool.close()
pool.join()

lN.sort()
with open("lN.bin","wb") as f:
    for n in lN:
        f.write(int(n).to_bytes(512//8,"big"))
