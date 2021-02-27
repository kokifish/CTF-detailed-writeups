# SageMath 9.2

import random
import time

def AMM(o, r, q):
    g = GF(q)
    o = g(o)
    p = g(random.randint(1, q))
    while p ^ ((q-1) // r) == 1:
        p = g(random.randint(1, q))
    t = 0
    s = q - 1
    while s % r == 0:
        t += 1
        s = s // r
    k = 1
    while (k * s + 1) % r != 0:
        k += 1
    alp = (k * s + 1) // r
    a = p ^ (r**(t-1) * s)
    b = o ^ (r*alp - 1)
    c = p ^ s
    h = 1
    for i in range(1, t):
        d = b ^ (r^(t-1-i))
        if d == 1:
            j = 0
        else:
            j = - dicreat_log(a, d)
        b = b * (c^r)^j
        h = h * c^j
        c = c ^ r
    result = o^alp * h
    return result

def findAllPRoot(p, e):
    proot = set()
    while len(proot) < e:
        proot.add(pow(random.randint(2, p-1), (p-1)//e, p))
    return proot

def findAllSolutions(mp, proot, cp, p):
    all_mp = set()
    for root in proot:
        mp2 = mp * root % p
        assert(pow(mp2, e, p) == cp)
        all_mp.add(mp2)
    return all_mp

c = 12732299056226934743176360461051108799706450051853623472248552066649321279227693844417404789169416642586313895494292082308084823101092675162498154181999270703392144766031531668783213589136974486867571090321426005719333327425286160436925591205840653712046866950957876967715226097699016798471712274797888761218915345301238306497841970203137048433491914195023230951832644259526895087301990301002618450573323078919808182376666320244077837033894089805640452791930176084416087344594957596135877833163152566525019063919662459299054294655118065279192807949989681674190983739625056255497842063989284921411358232926435537518406
p = 199138677823743837339927520157607820029746574557746549094921488292877226509198315016018919385259781238148402833316033634968163276198999279327827901879426429664674358844084491830543271625147280950273934405879341438429171453002453838897458102128836690385604150324972907981960626767679153125735677417397078196059
q = 112213695905472142415221444515326532320352429478341683352811183503269676555434601229013679319423878238944956830244386653674413411658696751173844443394608246716053086226910581400528167848306119179879115809778793093611381764939789057524575349501163689452810148280625226541609383166347879832134495444706697124741
e = 4919

start_time = time.time()
print("Start time: 0.0")
# find all roots for pow(x, e, p)=1 and pow(x, e, q)=1 
cp = c % p
cq = c % q
p_proot = findAllPRoot(p, e)
print("P roots found: %s" % str(time.time()-start_time))
q_proot = findAllPRoot(q, e)
print("Q roots found: %s" % str(time.time()-start_time))

# find all roots for pow(x, e, p)=cp and pow(x, e, q)=cq
mp = AMM(cp, e, p)
print("mp found: %s" % str(time.time()-start_time))
mq = AMM(cq, e, q)
print("mq found: %s" % str(time.time()-start_time))

mps = findAllSolutions(mp, p_proot, cp, p)
print("mps found: %s" % str(time.time()-start_time))
mqs = findAllSolutions(mq, q_proot, cq, q)
print("mqs found: %s" % str(time.time()-start_time))

def check(m):
    h = hex(int(m))[2:]
    if len(h) & 1:
        return False
    if bytes.fromhex(h).startswith(b'*CTF'):    
        print(bytes.fromhex(h))
        return True
    else:
        return False

# check 4919*4919 possibles for answer
for mpp in mps:
    for mqq in mqs:
        solution = CRT_list([int(mpp), int(mqq)], [p, q])
        if check(solution):
            print(solution)
            print("solution found: %s" % str(time.time()-start_time))