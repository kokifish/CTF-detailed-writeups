> fedora 33 64bit

```python
dnf install qume
[root@localhost CTF]# file ./file
./file: ELF 32-bit LSB executable, MIPS, N32 MIPS64 version 1 (SYSV), dynamically linked, interpreter /lib32/ld-uClibc.so.0, stripped
    
[root@localhost CTF]# qemu-mipsel ./mips         # rename to mips
/lib32/ld-uClibc.so.0: No such file or directory
```

