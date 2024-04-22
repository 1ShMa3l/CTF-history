from pwn import *

context.terminal = ["qterminal", "-e"]

p = process("./nf")
gdb.attach(p, "start")
pause()

p.sendline(b"\x00")

p.interactive()