from pwn import*

context(os="linux", arch="amd64")
# context(log_level="debug")
context.terminal = ["qterminal", "-e"]
p = process("./vuln1")
try:
    p.sendline('123')
    p.recvuntil(timeout=1)
except:
    log.info("mbot")
