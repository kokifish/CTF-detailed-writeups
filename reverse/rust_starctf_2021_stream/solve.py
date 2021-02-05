import os
import string

tab = string.printable
tab = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/{}_=-~!.@#%^&*()"
# '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ{}*'
sz = 46
arr = [0]*sz

with open('./output_ori','rb') as f:
    ct = f.read()

def se(i):
    global arr
    print(i, arr, ''.join(map(chr,arr)))
    if(i >= sz):
        print(''.join(map(chr,arr))) # finished
        exit()
    for ch in tab: # traversal all printable char
        idx = (7*i + 4) % sz # specific order
        arr[idx] = ord(ch)
        candidate = ''.join(map(chr, arr)) # a int array to a chr array
        with open('flag','wb') as f: # write to file: flag
            f.write(candidate.encode()) # encode: str to byte
        os.system("./task") # execute rust execution: task
        with open('output','rb') as f:
            outp = f.read() # read file: output
        if ct[idx] == outp[idx]:
            se(i+1)
        
#arr[:5] = [42, 99, 116, 102, 123]
se(0)